'''
Name: Onwurah Onyedikaahi Maryjane
Registration Number: 2024924046
Course Code: NAU-CYB 221
Department: Cyber Security
Faculty: Physical Science
'''

import psutil
import socket
import argparse
import json
import os
from datetime import datetime
from prettytable import PrettyTable

SENSITIVE_PORTS = {21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389}


def collect_sockets():
    """Get TCP LISTEN and UDP bound sockets."""
    try:
        conns = psutil.net_connections(kind='inet')
    except PermissionError:
        print("Run with sudo to see process names and PIDs")
        return []

    sockets = []
    for c in conns:
        if c.type == socket.SOCK_STREAM and c.status == psutil.CONN_LISTEN:
            sockets.append(c)
        elif c.type == socket.SOCK_DGRAM and c.laddr and not c.raddr:
            sockets.append(c)
    return sockets


def get_process_name(pid):
    if not pid:
        return "N/A"
    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return "N/A"


def get_service_name(port, proto):
    try:
        return socket.getservbyport(port, proto.lower())
    except OSError:
        return "Unknown"


def build_record(conn):
    addr = conn.laddr
    proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
    return {
        "protocol": proto,
        "port": addr.port,
        "local_address": addr.ip,
        "pid": conn.pid if conn.pid else "N/A",
        "process": get_process_name(conn.pid),
        "service": get_service_name(addr.port, proto),
        "risk": "Local-only" if addr.ip in ("127.0.0.1", "::1") else "Exposed",
        "flag": "High-Interest" if addr.port in SENSITIVE_PORTS else "Normal"
    }


def filter_and_sort(records, args):
    if args.tcp:
        records = [r for r in records if r["protocol"] == "TCP"]
    if args.udp:
        records = [r for r in records if r["protocol"] == "UDP"]
    if args.above is not None:
        records = [r for r in records if r["port"] > args.above]
    if args.below is not None:
        records = [r for r in records if r["port"] < args.below]

    # Sort: TCP first, then by port number
    records.sort(key=lambda r: (r["protocol"] != "TCP", r["port"]))
    return records


def print_table(records):
    if not records:
        print("No ports found (or none after filtering).")
        return

    t = PrettyTable([
        "Protocol", "Port", "Local Address", "PID", "Process",
        "Service", "Risk", "Flag"
    ])
    t.align = "l"

    for r in records:
        t.add_row([
            r["protocol"], r["port"], r["local_address"],
            r["pid"], r["process"], r["service"],
            r["risk"], r["flag"]
        ])

    print(f"\nLocal Ports Report – {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(t)


def save_reports(records):
    try:
        # Decide where to save based on whether we are root
        base_dir = "/tmp" if os.getuid() == 0 else "."
        txt_path = os.path.join(base_dir, "ports_report.txt")
        json_path = os.path.join(base_dir, "ports_report.json")

        # Text report
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write(f"Local Ports Report – {datetime.now()}\n\n")
            for r in records:
                f.write(
                    f"{r['protocol']} {r['port']} | {r['local_address']} | "
                    f"{r['process']} (PID {r['pid']}) | {r['service']} | "
                    f"{r['risk']} | {r['flag']}\n"
                )

        # JSON
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(records, f, indent=2)

        print(f"Reports saved to:")
        print(f"  TXT: {txt_path}")
        print(f"  JSON: {json_path}")

    except PermissionError as e:
        print(f"Permission denied writing files: {e}")
        print("Try running without sudo or check directory permissions.")
    except Exception as e:
        print(f"Failed to save reports: {e}")


def print_summary(records):
    if not records:
        return

    # Simple priority: Exposed + High-Interest first
    sorted_records = sorted(
        records,
        key=lambda r: (r["risk"] == "Exposed", r["flag"] == "High-Interest"),
        reverse=True
    )

    print("\nTop ports by security concern:")
    for r in sorted_records[:5]:
        print(
            f"  {r['protocol']} {r['port']} ({r['service']}) – "
            f"{r['risk']} / {r['flag']} – {r['process']} (PID {r['pid']})"
        )


def main():
    parser = argparse.ArgumentParser(description="Local port inspection – defensive use only")
    parser.add_argument("--tcp", action="store_true", help="show only TCP ports")
    parser.add_argument("--udp", action="store_true", help="show only UDP ports")
    parser.add_argument("--above", type=int, help="show ports > this number")
    parser.add_argument("--below", type=int, help="show ports < this number")
    args = parser.parse_args()

    sockets = collect_sockets()
    records = [build_record(c) for c in sockets]
    filtered = filter_and_sort(records, args)

    print_table(filtered)
    save_reports(filtered)
    print_summary(filtered)


if __name__ == "__main__":
    main()
