import sys
import statistics
from collections import defaultdict
from scapy.all import rdpcap
from parser import parse_packet

MIN_CONNECTIONS = 8    # need at least this many connections to judge
MAX_VARIATION = 0.2    # gaps must be within about 20% of the average gap
MIN_INTERVAL = 5       # ignore very fast repeats (seconds)


def detect_beaconing(packets):
    # Collect the time of every new connection (SYN), grouped by
    # (who connected, to which server, on which port)
    conns = defaultdict(list)
    for pkt in packets:
        info = parse_packet(pkt)
        if info and info["proto"] == "TCP" and info["flags"] == "S":
            key = (info["src"], info["dst"], info["dport"])
            conns[key].append(info["time"])

    alerts = []
    for (src, dst, dport), times in conns.items():
        if len(times) < MIN_CONNECTIONS:
            continue
        times.sort()
        gaps = [b - a for a, b in zip(times, times[1:])]
        average = statistics.mean(gaps)
        if average < MIN_INTERVAL:
            continue
        variation = statistics.pstdev(gaps) / average
        if variation <= MAX_VARIATION:
            alerts.append({
                "type": "Beaconing",
                "mitre": "T1071",
                "src": src,
                "dst": dst,
                "dport": dport,
                "connections": len(times),
                "interval": round(average, 1),
                "variation": round(variation, 2),
            })
    return alerts


if __name__ == "__main__":
    packets = rdpcap(sys.argv[1])
    alerts = detect_beaconing(packets)
    if not alerts:
        print("No beaconing detected.")
    for a in alerts:
        print(f"[ALERT] {a['type']} ({a['mitre']}): {a['src']} -> {a['dst']}:{a['dport']}, "
              f"{a['connections']} connections, every ~{a['interval']}s "
              f"(variation {a['variation']})")
