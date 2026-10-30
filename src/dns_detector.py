import sys
import math
from collections import Counter, defaultdict
from scapy.all import rdpcap, DNS, DNSQR, IP

MIN_LABEL_LEN = 25      # subdomain length considered suspicious
ENTROPY_LIMIT = 3.5     # randomness score (bits per character)
MIN_HITS = 5            # suspicious queries needed before alerting


def entropy(text):
    """Shannon entropy: higher means more random-looking."""
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def detect_dns_tunneling(packets):
    hits = defaultdict(list)
    for pkt in packets:
        if DNS in pkt and DNSQR in pkt and pkt[DNS].qr == 0 and IP in pkt:
            name = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
            labels = name.split(".")
            if len(labels) < 3:
                continue
            sub = ".".join(labels[:-2])   # everything before the base domain
            if len(sub) >= MIN_LABEL_LEN and entropy(sub) >= ENTROPY_LIMIT:
                hits[(pkt[IP].src, ".".join(labels[-2:]))].append(sub)

    alerts = []
    for (src, domain), subs in hits.items():
        if len(subs) >= MIN_HITS:
            alerts.append({
                "type": "DNS tunneling",
                "mitre": "T1071.004",
                "src": src,
                "domain": domain,
                "queries": len(subs),
                "example": subs[0],
            })
    return alerts


if __name__ == "__main__":
    packets = rdpcap(sys.argv[1])
    alerts = detect_dns_tunneling(packets)
    if not alerts:
        print("No DNS tunneling detected.")
    for a in alerts:
        print(f"[ALERT] {a['type']} ({a['mitre']}): {a['src']} -> {a['domain']}, "
              f"{a['queries']} suspicious queries, e.g. {a['example']}")