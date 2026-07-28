import datetime
from core.paths import LOG_PATH, ensure_data_dir


def log(message):
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    formatted = f'[{timestamp}] {message}'
    print(formatted)
    ensure_data_dir()
    with LOG_PATH.open('a', encoding='utf-8') as handle:
        handle.write(formatted + '\n')