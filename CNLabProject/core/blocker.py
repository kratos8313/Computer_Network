import os
import shutil
import subprocess
import tempfile
import threading
from pathlib import Path

from core.database import get_db
from core.proxy import clear_all_connections
from utils.logger import log
from utils.norm import get_domain_variants

HOSTS_PATH = Path(r'C:\Windows\System32\drivers\etc\hosts')
MARKER_START = '# BEGIN NETGUARD ACCESS CONTROL\n'
MARKER_END = '# END NETGUARD ACCESS CONTROL\n'
LEGACY_MARKER_START = '# BEGIN PARENTAL CONTROL\n'
LEGACY_MARKER_END = '# END PARENTAL CONTROL\n'
MANAGED_MARKERS = (
    (MARKER_START, MARKER_END),
    (LEGACY_MARKER_START, LEGACY_MARKER_END),
)
hosts_lock = threading.Lock()


def flush_dns():
    try:
        subprocess.run(['ipconfig', '/flushdns'], capture_output=True, check=True)
        clear_all_connections()
        log('[DNS] Flushed DNS and cleared active proxy connections.')
    except Exception as exc:
        log(f'[DNS ERROR] Failed to flush DNS: {exc}')


def load_sites_from_db():
    with get_db() as conn:
        rules = conn.execute("SELECT domain FROM rules WHERE action='block'").fetchall()
    return sorted({variant for row in rules for variant in get_domain_variants(row['domain'])})


def _managed_ranges(content):
    ranges = []
    for start_marker, end_marker in MANAGED_MARKERS:
        starts = [i for i, line in enumerate(content) if line == start_marker]
        ends = [i for i, line in enumerate(content) if line == end_marker]
        if len(starts) > 1 or len(ends) > 1:
            raise ValueError('Duplicate managed-policy markers in hosts file')
        if bool(starts) != bool(ends) or (starts and starts[0] >= ends[0]):
            raise ValueError('Malformed managed-policy markers in hosts file')
        if starts:
            ranges.append((starts[0], ends[0]))
    ranges.sort()
    if any(current[0] <= previous[1] for previous, current in zip(ranges, ranges[1:])):
        raise ValueError('Overlapping managed-policy markers in hosts file')
    return ranges


def _without_managed_blocks(content):
    result = list(content)
    for start, end in reversed(_managed_ranges(content)):
        del result[start:end + 1]
    return result


def managed_content(content, sites):
    unmanaged = _without_managed_blocks(content)
    block = [MARKER_START]
    for site in sites:
        block.extend((f'127.0.0.1 {site}\n', f'::1 {site}\n'))
    block.append(MARKER_END)
    separator = ['\n'] if unmanaged and not unmanaged[-1].endswith('\n') else []
    return unmanaged + separator + block


def atomic_write(lines):
    backup = HOSTS_PATH.with_suffix('.netguard.bak')
    shutil.copy2(HOSTS_PATH, backup)
    fd, temporary = tempfile.mkstemp(dir=HOSTS_PATH.parent, prefix='hosts.', text=True)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='') as handle:
            handle.writelines(lines)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, HOSTS_PATH)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def block_sites():
    with hosts_lock:
        try:
            content = HOSTS_PATH.read_text(encoding='utf-8').splitlines(keepends=True)
            final = managed_content(content, load_sites_from_db())
            if final != content:
                atomic_write(final)
                flush_dns()
        except PermissionError:
            log('[ERROR] Run as Administrator to update the hosts file.')
        except Exception as exc:
            log(f'[ERROR] Failed to synchronize hosts file: {exc}')


def unblock_all():
    with hosts_lock:
        try:
            content = HOSTS_PATH.read_text(encoding='utf-8').splitlines(keepends=True)
            final = _without_managed_blocks(content)
            if final != content:
                atomic_write(final)
                flush_dns()
        except PermissionError:
            log('[ERROR] Run as Administrator to restore the hosts file.')
        except Exception as exc:
            log(f'[ERROR] Failed to unblock: {exc}')