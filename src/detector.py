import sys
from collections import defaultdict
from scapy.all import rdpcap
from parser import parse_packet

THRESHOLD = 20   # unique ports needed to raise an alert
WINDOW = 10      # seconds


def detect_port_scans(packets):
    # Collect every SYN, grouped by (source, target)
    syns = defaultdict(list)
    for pkt in packets:
        info = parse_packet(pkt)
        if info and info["proto"] == "TCP" and info["flags"] == "S":
            syns[(info["src"], info["dst"])].append((info["time"], info["dport"]))

    alerts = []
    for (src, dst), events in syns.items():
        events.sort()
        start = 0
        best = 0
        for end in range(len(events)):
            # shrink the window until it is at most WINDOW seconds long
            while events[end][0] - events[start][0] > WINDOW:
                start += 1
            ports = {p for _, p in events[start:end + 1]}
            best = max(best, len(ports))
        if best >= THRESHOLD:
            alerts.append({
                "type": "Port scan",
                "mitre": "T1046",
                "src": src,
                "dst": dst,
                "unique_ports": best,
            })
    return alerts


if __name__ == "__main__":
    packets = rdpcap(sys.argv[1])
    alerts = detect_port_scans(packets)
    if not alerts:
        print("No port scans detected.")
    for a in alerts:
        print(f"[ALERT] {a['type']} ({a['mitre']}): {a['src']} -> {a['dst']}, "
              f"{a['unique_ports']} unique ports")
