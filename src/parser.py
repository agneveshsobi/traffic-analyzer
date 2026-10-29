import sys
from scapy.all import rdpcap, IP, TCP, UDP, DNS


def parse_packet(pkt):
    """Extract the fields we care about from one packet. Returns None if not IP."""
    if IP not in pkt:
        return None

    info = {
        "time": float(pkt.time),
        "src": pkt[IP].src,
        "dst": pkt[IP].dst,
        "proto": "OTHER",
        "sport": None,
        "dport": None,
        "flags": None,
    }

    if TCP in pkt:
        info["proto"] = "TCP"
        info["sport"] = pkt[TCP].sport
        info["dport"] = pkt[TCP].dport
        info["flags"] = str(pkt[TCP].flags)
    elif UDP in pkt:
        info["proto"] = "UDP"
        info["sport"] = pkt[UDP].sport
        info["dport"] = pkt[UDP].dport
        if DNS in pkt:
            info["proto"] = "DNS"

    return info


def main(path):
    packets = rdpcap(path)
    print(f"Loaded {len(packets)} packets\n")
    for pkt in packets[:30]:
        info = parse_packet(pkt)
        if info:
            print(
                f"{info['time']:.3f}  {info['proto']:<5} "
                f"{info['src']}:{info['sport']} -> {info['dst']}:{info['dport']} "
                f"flags={info['flags']}"
            )


if __name__ == "__main__":
    main(sys.argv[1])
