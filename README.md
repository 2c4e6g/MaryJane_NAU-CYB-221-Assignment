# MaryJane_NAU-CYB-221-Assignment

Name: Onwurah Onyedikaahi Maryjane

Registration Number: 2024924046

Course Code: NAU-CYB 221

Level: 200 Level

Department: Cyber Security

Faculty: Physical Sciences


##################################

Local Listening Ports Enumerator (Defensive – Local Machine Only)
NAU-CYB 221 – Cybersecurity Technology

Scans TCP listening ports and UDP bound sockets on the local machine using psutil.
Displays protocol, port, bind address, PID/process name (requires sudo), service name, risk level (Local-only vs Exposed), and high-interest flags.
Outputs formatted terminal table, text log, JSON file, and top security concern summary.

Scope: Local machine only. No remote scanning or network probing.

Requirements
- Python 3
- pip install psutil prettytable
- Tested on ChromeOS Crostini (Debian-based Linux container)

Installation
python3 -m venv venv
source venv/bin/activate
pip install psutil prettytable

Usage
For full process/PID visibility (recommended):

sudo venv/bin/python3 scanner.py

Filters

sudo venv/bin/python3 scanner.py --tcp     # TCP ports only

sudo venv/bin/python3 scanner.py --udp     # UDP ports only

sudo venv/bin/python3 scanner.py --above 100  # ports > 100

sudo venv/bin/python3 scanner.py --below 1000 # ports < 1000


Outputs
- Terminal: PrettyTable + top security concern summary
- ports_report.txt (text list)
- ports_report.json (structured data)

Sample Output (ChromeOS Crostini, sudo run – February 2026)

Local Ports Report – 2026-02-28 22:46:40

+----------+------+---------------+-----+----------+---------+---------+--------+

| Protocol | Port | Local Address | PID | Process  | Service | Risk    | Flag   |

+----------+------+---------------+-----+----------+---------+---------+--------+

| UDP      | 68   | 0.0.0.0       | 111 | dhclient | bootpc  | Exposed | Normal |

+----------+------+---------------+-----+----------+---------+---------+--------+

Reports saved to:

  - TXT: /tmp/ports_report.txt
  
  - JSON: /tmp/ports_report.json
  

Top ports by security concern:
  UDP 68 (bootpc) – Exposed / Normal – dhclient (PID 111)

Limitations
- UDP detection uses bound sockets only (no true LISTEN state for UDP)
- PID and process names require sudo (otherwise N/A)
- ChromeOS Crostini shows very few ports due to container isolation and host firewalling
- Service name mapping fails on non-standard or custom ports

Ethical Statement
This tool inspects only the local machine. No external IPs or networks were scanned. Used exclusively on personally owned Chromebook.
