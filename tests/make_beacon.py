import random
from scapy.all import Ether, IP, TCP, wrpcap

packets = []
t = 1700000000.0
for i in range(15):
    pkt = (
        Ether(dst="aa:bb:cc:dd:ee:ff")
        / IP(src="192.168.56.10", dst="203.0.113.50")
        / TCP(sport=40000 + i, dport=443, flags="S")
    )
    pkt.time = t
    packets.append(pkt)
    t += 60 + random.uniform(-3, 3)   # every ~60 seconds, small random shift

wrpcap("data/beacon.pcap", packets)
print("Wrote data/beacon.pcap with", len(packets), "packets")
