import argparse
import json
from scapy.all import rdpcap
from detector import detect_port_scans
from dns_detector import detect_dns_tunneling
from beacon_detector import detect_beaconing

DETECTORS = [
    ("Port scan", detect_port_scans),
    ("DNS tunneling", detect_dns_tunneling),
    ("Beaconing", detect_beaconing),
]


def main():
    parser = argparse.ArgumentParser(description="Analyze a pcap for suspicious traffic.")
    parser.add_argument("capture", help="path to a .pcap or .pcapng file")
    parser.add_argument("--json", metavar="FILE", help="also save alerts to a JSON file")
    args = parser.parse_args()

    packets = rdpcap(args.capture)
    print(f"Analyzing {args.capture} ({len(packets)} packets)\n")
    all_alerts = []
    for name, run in DETECTORS:
        alerts = run(packets)
        all_alerts.extend(alerts)
        if not alerts:
            print(f"[ok]    {name}: nothing found")
        for a in alerts:
            details = ", ".join(
                f"{k}={v}" for k, v in a.items() if k not in ("type", "mitre")
            )
            print(f"[ALERT] {a['type']} ({a['mitre']}): {details}")
    print(f"\nDone. {len(all_alerts)} alert(s).")

    if args.json:
        with open(args.json, "w") as f:
            json.dump(all_alerts, f, indent=2)
        print(f"Saved alerts to {args.json}")


if __name__ == "__main__":
    main()
