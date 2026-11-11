import sys
from scapy.all import rdpcap
from detector import detect_port_scans
from dns_detector import detect_dns_tunneling
from beacon_detector import detect_beaconing

DETECTORS = [
    ("Port scan", detect_port_scans),
    ("DNS tunneling", detect_dns_tunneling),
    ("Beaconing", detect_beaconing),
]


def main(path):
    packets = rdpcap(path)
    print(f"Analyzing {path} ({len(packets)} packets)\n")
    total = 0
    for name, run in DETECTORS:
        alerts = run(packets)
        total += len(alerts)
        if not alerts:
            print(f"[ok]    {name}: nothing found")
        for a in alerts:
            details = ", ".join(
                f"{k}={v}" for k, v in a.items() if k not in ("type", "mitre")
            )
            print(f"[ALERT] {a['type']} ({a['mitre']}): {details}")
    print(f"\nDone. {total} alert(s).")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python src/analyzer.py <capture.pcap>")
        sys.exit(1)
    main(sys.argv[1])
