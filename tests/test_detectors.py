import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest
from scapy.all import rdpcap
from detector import detect_port_scans
from dns_detector import detect_dns_tunneling
from beacon_detector import detect_beaconing

DATA = os.path.join(os.path.dirname(__file__), "..", "data")


def load(name):
    path = os.path.join(DATA, name)
    if not os.path.exists(path):
        pytest.skip(f"{name} not found")
    return rdpcap(path)


def test_port_scan_detected():
    assert len(detect_port_scans(load("portscan.pcapng"))) >= 1


def test_port_scan_quiet_on_normal():
    assert detect_port_scans(load("normal.pcapng")) == []


def test_dns_tunnel_detected():
    assert len(detect_dns_tunneling(load("dns_tunnel.pcap"))) >= 1


def test_dns_quiet_on_normal():
    assert detect_dns_tunneling(load("normal.pcapng")) == []


def test_beacon_detected():
    assert len(detect_beaconing(load("beacon.pcap"))) >= 1


def test_beacon_quiet_on_normal():
    assert detect_beaconing(load("normal.pcapng")) == []


def test_beacon_quiet_on_portscan():
    assert detect_beaconing(load("portscan.pcapng")) == []
