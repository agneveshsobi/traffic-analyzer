# Network Traffic Analyzer

A Python tool that reads network captures (.pcap/.pcapng) and detects
suspicious behavior. Built with Scapy as a cybersecurity learning project.

## Detections

| Detection | Technique | MITRE ATT&CK |
| Port scan | One host sends SYNs to 20+ ports within 10 seconds | T1046 |
| DNS tunneling | Long, high-entropy subdomains queried repeatedly | T1071.004 |

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
| Synthetic DNS tunnel (20 queries) | DNS tunneling alert | Detected |
| Normal traffic | No alert | No false positive |

## Roadmap

- Beaconing detection
- ARP spoofing detection
- Tests on real-world attack captures
- Alert export (JSON) and dashboard
