# Network Traffic Analyzer

A Python tool that reads network captures (.pcap/.pcapng) and detects
suspicious behavior. Built with Scapy as a cybersecurity learning project.

## Detections

| Detection | Technique | MITRE ATT&CK |
|---|---|---|
| Port scan | One host sends SYNs to 20+ ports within 10 seconds | T1046 |
| DNS tunneling | Long, high-entropy subdomains queried repeatedly | T1071.004 |
   | Beaconing | Same host contacts the same server at regular intervals (8+ connections, gaps within 20% of average) | T1071 |

## How it works

pcap file -> parser.py (decode packets) -> detectors -> alerts

## Usage

    pip install scapy
    python src/detector.py data/portscan.pcapng
    python src/dns_detector.py data/dns_tunnel.pcap

## Results

| Test file | Expected | Result |
|---|---|---|
| nmap SYN scan (1000 ports) | Port scan alert | Detected |
| Normal traffic (ping, curl) | No alert | No false positive |
| Synthetic DNS tunnel (20 queries) | DNS tunneling alert | Detected (synthetic data) |
| Normal traffic | No DNS alert | No false positive |
| Real capture (malware-traffic-analysis.net, 2026-10-01) | No port scan | No alert |
   | Synthetic beacon (15 connections, ~60s apart) | Beaconing alert | Detected (synthetic data) |

## Real-data testing: a false positive found and fixed

I ran the DNS detector on a real capture from malware-traffic-analysis.net
(exercise 2026-10-01). It raised a DNS tunneling alert for one host.

Investigating the alert in Wireshark showed the queries were readable
Active Directory lookups (for example `_kerberos._tcp...._msdcs`), which
Windows domain computers make routinely. They are long and use many
different characters, so my entropy rule scored them as suspicious.

**Fix:** the detector now skips names that contain a label starting with
an underscore (Windows service records).

**Verification after the fix:**
- Real capture: no DNS tunneling alert
- Synthetic tunnel file: still detected

**Lesson:** a high entropy score alone is not enough. Legitimate traffic
can look random, so rules need to be tested on real captures.

## Roadmap


- ARP spoofing detection
- Flow tracker, config file, automated tests
- Alert export (JSON) and dashboard
