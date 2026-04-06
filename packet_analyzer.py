#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║     Network Traffic Analyzer + Deep Packet Inspection        ║
║     College Project Tool — Team of 5                         ║
║     Uses: scapy (real packet capture)                        ║
║     Run as Administrator/root for live capture               ║
╚══════════════════════════════════════════════════════════════╝


INSTALL REQUIREMENTS FIRST:
    pip install scapy colorama

RUN (Windows - must be Administrator):
    python packet_analyzer.py

RUN (Linux/Mac - must be root):
    sudo python3 packet_analyzer.py
"""

import sys
import os
import time
import json
import csv
from datetime import datetime
from collections import Counter, defaultdict

# ── Dependency check ──────────────────────────────────────────
try:
    from scapy.all import (
        sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR,
        Raw, Ether, get_if_list, conf, wrpcap
    )
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
except ImportError:
    print("\n[ERROR] scapy is not installed.")
    print("  Run: pip install scapy")
    print("  Then re-run this script.\n")
    sys.exit(1)

try:
    from colorama import Fore, Back, Style, init
    init(autoreset=True)
    COLOR = True
except ImportError:
    COLOR = False
    class Fore:
        CYAN=RED=GREEN=YELLOW=MAGENTA=WHITE=BLUE=RESET=''
    class Style:
        BRIGHT=RESET_ALL=DIM=''

# ══════════════════════════════════════════════════════════════
#  GLOBALS
# ══════════════════════════════════════════════════════════════
captured_packets   = []
protocol_counter   = Counter()
ip_counter         = Counter()
dns_queries        = []
http_requests      = []
tcp_streams        = defaultdict(list)
total_bytes        = 0
start_time         = None
capture_running    = False
save_pcap          = False
pcap_filename      = ""

# ══════════════════════════════════════════════════════════════
#  DISPLAY HELPERS
# ══════════════════════════════════════════════════════════════
def banner():
    print(Fore.CYAN + Style.BRIGHT + """
╔══════════════════════════════════════════════════════════════╗
║        NETWORK TRAFFIC ANALYZER + DPI TOOL                   ║
║        Real Packet Capture using Scapy                       ║
║        College Project — Wireshark + DPI Concept             ║
╚══════════════════════════════════════════════════════════════╝""")
    print(Fore.WHITE + Style.DIM + "  Captures live packets · Filters protocols · Inspects payloads\n")

def c(text, color):
    return color + Style.BRIGHT + str(text) + Style.RESET_ALL if COLOR else str(text)

def separator(char="─", width=65):
    print(Fore.WHITE + Style.DIM + char * width)

def section(title):
    print()
    separator("═")
    print(c(f"  {title}", Fore.CYAN))
    separator("═")

def log_packet(proto, src, dst, size, info=""):
    colors = {
        "HTTP":  Fore.CYAN,
        "HTTPS": Fore.BLUE,
        "DNS":   Fore.GREEN,
        "TCP":   Fore.YELLOW,
        "UDP":   Fore.MAGENTA,
        "ICMP":  Fore.RED,
        "OTHER": Fore.WHITE,
    }
    color = colors.get(proto, Fore.WHITE)
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    proto_str = c(f"{proto:<6}", color)
    print(f"  {Style.DIM}{ts}{Style.RESET_ALL}  {proto_str}  "
          f"{c(src, Fore.WHITE):<20} → {c(dst, Fore.WHITE):<20}  "
          f"{Style.DIM}{size}B{Style.RESET_ALL}  {Fore.WHITE + Style.DIM}{info[:50]}{Style.RESET_ALL}")

# ══════════════════════════════════════════════════════════════
#  PACKET PROCESSING — THE CORE ENGINE
# ══════════════════════════════════════════════════════════════
def process_packet(pkt):
    global total_bytes

    if not pkt.haslayer(IP):
        return  # skip non-IP packets

    src_ip  = pkt[IP].src
    dst_ip  = pkt[IP].dst
    size    = len(pkt)

    total_bytes += size
    ip_counter[src_ip] += 1
    ip_counter[dst_ip] += 1
    captured_packets.append(pkt)

    # ── DNS Analysis (Deep Packet Inspection) ──────────────
    if pkt.haslayer(DNS):
        protocol_counter["DNS"] += 1

        # DPI: Read the actual domain name being queried
        if pkt.haslayer(DNSQR):
            try:
                qname = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
                qtype = pkt[DNSQR].qtype  # 1=A, 28=AAAA, 15=MX
                type_map = {1:"A", 28:"AAAA", 15:"MX", 5:"CNAME", 16:"TXT", 255:"ANY"}
                qtype_str = type_map.get(qtype, str(qtype))

                entry = {
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "src":  src_ip,
                    "query": qname,
                    "type":  qtype_str
                }
                dns_queries.append(entry)
                log_packet("DNS", src_ip, dst_ip, size,
                           f"Query [{qtype_str}] {qname}")
            except Exception:
                pass

        # DPI: Read DNS response IPs
        elif pkt[DNS].qr == 1 and pkt.haslayer(DNSRR):
            try:
                name = pkt[DNSRR].rrname.decode("utf-8", errors="ignore").rstrip(".")
                rdata = pkt[DNSRR].rdata
                log_packet("DNS", src_ip, dst_ip, size,
                           f"Response: {name} → {rdata}")
            except Exception:
                pass
        return

    # ── HTTP Analysis (Deep Packet Inspection) ─────────────
    if pkt.haslayer(HTTPRequest):
        protocol_counter["HTTP"] += 1
        try:
            method  = pkt[HTTPRequest].Method.decode("utf-8", errors="ignore")
            host    = pkt[HTTPRequest].Host.decode("utf-8", errors="ignore")
            path    = pkt[HTTPRequest].Path.decode("utf-8", errors="ignore")
            ua_raw  = pkt[HTTPRequest].fields.get("User-Agent", b"")
            ua      = ua_raw.decode("utf-8", errors="ignore") if isinstance(ua_raw, bytes) else str(ua_raw)

            entry = {
                "time":   datetime.now().strftime("%H:%M:%S"),
                "src":    src_ip,
                "method": method,
                "host":   host,
                "path":   path,
                "ua":     ua[:80]
            }
            http_requests.append(entry)
            log_packet("HTTP", src_ip, dst_ip, size,
                       f"{method} http://{host}{path[:30]}")
        except Exception:
            pass
        return

    if pkt.haslayer(HTTPResponse):
        protocol_counter["HTTP"] += 1
        try:
            status = pkt[HTTPResponse].Status_Code.decode("utf-8", errors="ignore")
            log_packet("HTTP", src_ip, dst_ip, size, f"Response {status}")
        except Exception:
            pass
        return

    # ── TCP Analysis ────────────────────────────────────────
    if pkt.haslayer(TCP):
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        flags = pkt[TCP].flags

        # Identify HTTPS by port 443
        if dport == 443 or sport == 443:
            protocol_counter["HTTPS"] += 1
            flag_str = str(flags)
            log_packet("HTTPS", src_ip, dst_ip, size,
                       f"Port 443 · Flags:{flag_str} (Encrypted)")
        else:
            protocol_counter["TCP"] += 1
            flag_str = str(flags)
            stream_key = f"{min(src_ip,dst_ip)}:{min(sport,dport)}"
            tcp_streams[stream_key].append(pkt)
            log_packet("TCP", src_ip, dst_ip, size,
                       f":{sport} → :{dport} Flags:{flag_str}")
        return

    # ── UDP Analysis ────────────────────────────────────────
    if pkt.haslayer(UDP):
        protocol_counter["UDP"] += 1
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
        log_packet("UDP", src_ip, dst_ip, size,
                   f":{sport} → :{dport}")
        return

    # ── ICMP Analysis ────────────────────────────────────────
    if pkt.haslayer(ICMP):
        protocol_counter["ICMP"] += 1
        icmp_type = pkt[ICMP].type
        type_map = {0:"Echo Reply", 8:"Echo Request", 3:"Dest Unreachable",
                    11:"TTL Exceeded"}
        icmp_str = type_map.get(icmp_type, f"Type {icmp_type}")
        log_packet("ICMP", src_ip, dst_ip, size, icmp_str)
        return

    # ── Other ────────────────────────────────────────────────
    protocol_counter["OTHER"] += 1

# ══════════════════════════════════════════════════════════════
#  STATISTICS & REPORTS
# ══════════════════════════════════════════════════════════════
def print_statistics():
    section("CAPTURE STATISTICS")

    elapsed = time.time() - start_time if start_time else 0
    total   = sum(protocol_counter.values())

    print(f"\n  {'Duration':<25} {elapsed:.1f} seconds")
    print(f"  {'Total Packets':<25} {total}")
    print(f"  {'Total Data':<25} {total_bytes/1024:.2f} KB  ({total_bytes/1024/1024:.3f} MB)")
    print(f"  {'Packets/sec':<25} {total/elapsed:.1f}" if elapsed > 0 else "")

    # Protocol breakdown
    print(f"\n  {c('Protocol Distribution:', Fore.CYAN)}")
    separator()
    bar_colors = {
        "HTTP": Fore.CYAN, "HTTPS": Fore.BLUE, "DNS": Fore.GREEN,
        "TCP": Fore.YELLOW, "UDP": Fore.MAGENTA,
        "ICMP": Fore.RED, "OTHER": Fore.WHITE
    }
    for proto, count in protocol_counter.most_common():
        if total > 0:
            pct  = count / total * 100
            bars = int(pct / 2)
            bar  = "█" * bars + "░" * (50 - bars)
            color = bar_colors.get(proto, Fore.WHITE)
            print(f"  {color}{proto:<8}{Style.RESET_ALL}  "
                  f"{color}{bar[:40]}{Style.RESET_ALL}  "
                  f"{count:>5} pkts  {pct:>5.1f}%")

    # Top IPs
    print(f"\n  {c('Top 10 IP Addresses (Most Active):', Fore.CYAN)}")
    separator()
    for ip, count in ip_counter.most_common(10):
        print(f"  {Fore.WHITE}{ip:<22}{Style.RESET_ALL}  {count:>5} packets")

def print_dpi_report():
    section("DEEP PACKET INSPECTION REPORT")

    # DNS Findings
    print(f"\n  {c('DNS Queries Captured (DPI — Payload Read):', Fore.GREEN)}")
    separator()
    if dns_queries:
        seen = set()
        for q in dns_queries:
            key = q['query']
            if key not in seen:
                seen.add(key)
                print(f"  {Style.DIM}{q['time']}{Style.RESET_ALL}  "
                      f"{Fore.GREEN}[{q['type']}]{Style.RESET_ALL}  "
                      f"{Fore.WHITE}{q['query']}{Style.RESET_ALL}  "
                      f"{Style.DIM}from {q['src']}{Style.RESET_ALL}")
        print(f"\n  {Style.DIM}Total unique domains queried: {len(seen)}{Style.RESET_ALL}")
    else:
        print(f"  {Style.DIM}No DNS queries captured. Try browsing a website.{Style.RESET_ALL}")

    # HTTP Findings
    print(f"\n  {c('HTTP Requests Captured (DPI — URL + Headers Read):', Fore.CYAN)}")
    separator()
    if http_requests:
        for r in http_requests[:20]:  # show max 20
            print(f"  {Style.DIM}{r['time']}{Style.RESET_ALL}  "
                  f"{Fore.CYAN}{r['method']:<5}{Style.RESET_ALL}  "
                  f"{Fore.WHITE}http://{r['host']}{r['path'][:40]}{Style.RESET_ALL}")
        if len(http_requests) > 20:
            print(f"  {Style.DIM}... and {len(http_requests)-20} more HTTP requests{Style.RESET_ALL}")
    else:
        print(f"  {Style.DIM}No HTTP requests captured.")
        print(f"  Note: Most modern sites use HTTPS (encrypted). Try http://example.com{Style.RESET_ALL}")

    # HTTPS note
    https_count = protocol_counter.get("HTTPS", 0)
    if https_count > 0:
        print(f"\n  {c('HTTPS Traffic (DPI Limitation):', Fore.BLUE)}")
        separator()
        print(f"  {Fore.BLUE}{https_count} HTTPS packets{Style.RESET_ALL} were captured but "
              f"payload is {c('encrypted (TLS)', Fore.RED)}.")
        print(f"  {Style.DIM}Only metadata visible: IP addresses, port 443, TLS handshake.")
        print(f"  This is the core limitation of DPI on encrypted traffic.{Style.RESET_ALL}")

def print_anomalies():
    section("ANOMALY DETECTION")

    found = False

    # High packet count from single IP
    for ip, count in ip_counter.most_common(5):
        if count > 100:
            found = True
            print(f"  {c('⚠ HIGH TRAFFIC', Fore.RED)}  {ip}  →  {count} packets  "
                  f"{Style.DIM}(possible scanner or high-use app){Style.RESET_ALL}")

    # ICMP flood check
    if protocol_counter.get("ICMP", 0) > 20:
        found = True
        print(f"  {c('⚠ ICMP FLOOD?', Fore.YELLOW)}  "
              f"{protocol_counter['ICMP']} ICMP packets detected  "
              f"{Style.DIM}(could be repeated ping){Style.RESET_ALL}")

    # DNS spam check
    if len(dns_queries) > 50:
        found = True
        print(f"  {c('⚠ HIGH DNS QUERIES', Fore.YELLOW)}  "
              f"{len(dns_queries)} DNS queries  "
              f"{Style.DIM}(possible tracking or app beaconing){Style.RESET_ALL}")

    if not found:
        print(f"  {Fore.GREEN}✔  No obvious anomalies detected in this capture.{Style.RESET_ALL}")

# ══════════════════════════════════════════════════════════════
#  SAVE REPORTS TO FILES
# ══════════════════════════════════════════════════════════════
def save_reports():
    section("SAVING REPORTS")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Save DNS report as CSV
    dns_file = f"dns_report_{timestamp}.csv"
    with open(dns_file, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["time","src","query","type"])
        writer.writeheader()
        writer.writerows(dns_queries)
    print(f"  {Fore.GREEN}✔{Style.RESET_ALL} DNS queries saved  →  {dns_file}")

    # Save HTTP report as CSV
    http_file = f"http_report_{timestamp}.csv"
    with open(http_file, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["time","src","method","host","path","ua"])
        writer.writeheader()
        writer.writerows(http_requests)
    print(f"  {Fore.GREEN}✔{Style.RESET_ALL} HTTP requests saved →  {http_file}")

    # Save summary as JSON
    summary = {
        "capture_time": datetime.now().isoformat(),
        "total_packets": sum(protocol_counter.values()),
        "total_bytes": total_bytes,
        "protocol_distribution": dict(protocol_counter),
        "top_ips": dict(ip_counter.most_common(10)),
        "dns_queries_count": len(dns_queries),
        "http_requests_count": len(http_requests),
        "unique_domains": list({q["query"] for q in dns_queries})
    }
    json_file = f"summary_{timestamp}.json"
    with open(json_file, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"  {Fore.GREEN}✔{Style.RESET_ALL} Summary saved       →  {json_file}")

    # Save .pcap file
    if captured_packets:
        pcap_file = f"capture_{timestamp}.pcap"
        wrpcap(pcap_file, captured_packets)
        print(f"  {Fore.GREEN}✔{Style.RESET_ALL} PCAP file saved      →  {pcap_file}  "
              f"{Style.DIM}(open in Wireshark){Style.RESET_ALL}")

    print(f"\n  {Style.DIM}All files saved in current directory: {os.getcwd()}{Style.RESET_ALL}")

# ══════════════════════════════════════════════════════════════
#  INTERFACE SELECTION
# ══════════════════════════════════════════════════════════════
def choose_interface():
    section("SELECT NETWORK INTERFACE")
    interfaces = get_if_list()

    print(f"  {Style.DIM}Available network interfaces on your machine:{Style.RESET_ALL}\n")
    for i, iface in enumerate(interfaces):
        marker = Fore.CYAN + "  [Wi-Fi likely]" + Style.RESET_ALL if any(
            x in iface.lower() for x in ["wi-fi","wlan","wifi","wireless","wi_fi"]) else ""
        eth_marker = Fore.YELLOW + "  [Ethernet likely]" + Style.RESET_ALL if any(
            x in iface.lower() for x in ["eth","local area","ethernet"]) else ""
        print(f"  {Fore.WHITE}[{i}]{Style.RESET_ALL}  {iface}{marker}{eth_marker}")

    print()
    while True:
        try:
            choice = input(f"  {Fore.CYAN}Enter interface number (or press Enter for default): {Style.RESET_ALL}").strip()
            if choice == "":
                selected = conf.iface
                print(f"  Using default: {Fore.GREEN}{selected}{Style.RESET_ALL}")
                return selected
            idx = int(choice)
            if 0 <= idx < len(interfaces):
                selected = interfaces[idx]
                print(f"  Selected: {Fore.GREEN}{selected}{Style.RESET_ALL}")
                return selected
            else:
                print(f"  {Fore.RED}Invalid number. Try again.{Style.RESET_ALL}")
        except ValueError:
            print(f"  {Fore.RED}Please enter a number.{Style.RESET_ALL}")

# ══════════════════════════════════════════════════════════════
#  CAPTURE SETTINGS
# ══════════════════════════════════════════════════════════════
def choose_settings():
    section("CAPTURE SETTINGS")

    # Packet count
    print(f"  {Style.DIM}How many packets to capture?{Style.RESET_ALL}")
    print(f"  {Style.DIM}(Recommended: 100–500 for a quick test, 0 = unlimited until Ctrl+C){Style.RESET_ALL}\n")
    while True:
        try:
            n = input(f"  {Fore.CYAN}Packet count [default 200]: {Style.RESET_ALL}").strip()
            count = int(n) if n else 200
            break
        except ValueError:
            print(f"  {Fore.RED}Enter a number.{Style.RESET_ALL}")

    # Filter
    print(f"\n  {Style.DIM}Apply a BPF capture filter? (Leave blank to capture everything){Style.RESET_ALL}")
    print(f"  {Style.DIM}Examples:  tcp port 80   |   udp   |   host 8.8.8.8   |   icmp{Style.RESET_ALL}\n")
    bpf = input(f"  {Fore.CYAN}Filter [default: none]: {Style.RESET_ALL}").strip() or None

    # Save pcap
    save = input(f"\n  {Fore.CYAN}Save capture as .pcap file? (y/n) [default y]: {Style.RESET_ALL}").strip().lower()
    save_pcap = save != "n"

    return count, bpf, save_pcap

# ══════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════
def main():
    global start_time

    banner()

    # Check privileges
    if os.name == "nt":
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print(f"\n  {Fore.RED}[ERROR] Run this script as Administrator on Windows.{Style.RESET_ALL}")
            print(f"  {Style.DIM}Right-click Command Prompt → 'Run as administrator' → then run the script.{Style.RESET_ALL}\n")
            sys.exit(1)
    else:
        if os.geteuid() != 0:
            print(f"\n  {Fore.RED}[ERROR] Run this script as root on Linux/Mac.{Style.RESET_ALL}")
            print(f"  {Style.DIM}Use: sudo python3 packet_analyzer.py{Style.RESET_ALL}\n")
            sys.exit(1)

    # Select interface & settings
    iface        = choose_interface()
    count, bpf, do_save = choose_settings()

    # Start capture
    section("LIVE PACKET CAPTURE — STARTING")
    print(f"  Interface : {Fore.GREEN}{iface}{Style.RESET_ALL}")
    print(f"  Count     : {Fore.GREEN}{'Unlimited (Ctrl+C to stop)' if count == 0 else count}{Style.RESET_ALL}")
    print(f"  Filter    : {Fore.GREEN}{bpf if bpf else 'None (capturing all protocols)'}{Style.RESET_ALL}")
    print(f"\n  {Fore.YELLOW}TIP: Open your browser and visit some websites while capturing!{Style.RESET_ALL}")
    print(f"  {Fore.YELLOW}     Run: ping google.com  in another terminal window{Style.RESET_ALL}")
    print(f"\n  {Style.DIM}{'─'*65}{Style.RESET_ALL}")
    print(f"  {'TIME':<15}  {'PROTO':<7}  {'SRC':<20}  {'DST':<20}  {'SIZE':<6}  INFO")
    print(f"  {Style.DIM}{'─'*65}{Style.RESET_ALL}\n")

    start_time = time.time()

    try:
        sniff(
            iface=iface,
            prn=process_packet,
            count=count if count > 0 else 0,
            filter=bpf,
            store=False
        )
    except KeyboardInterrupt:
        print(f"\n\n  {Fore.YELLOW}Capture stopped by user (Ctrl+C){Style.RESET_ALL}")
    except Exception as e:
        print(f"\n  {Fore.RED}Capture error: {e}{Style.RESET_ALL}")
        print(f"  {Style.DIM}Make sure you are running as Administrator/root.{Style.RESET_ALL}")

    # Show results
    print_statistics()
    print_dpi_report()
    print_anomalies()

    if do_save:
        save_reports()

    print()
    separator("═")
    print(c("  CAPTURE COMPLETE", Fore.CYAN))
    separator("═")
    print(f"\n  {Style.DIM}Open the saved .pcap file in Wireshark for full visual analysis.{Style.RESET_ALL}\n")

if __name__ == "__main__":
    main()
