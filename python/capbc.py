#!/usr/bin/python3

import pcap
import dpkt
import aplist

def mac2str(mac):
    return ':'.join(map('{:02X}'.format, mac))

def sniff(network_interface):
    sniffer = pcap.pcap(name=network_interface, promisc=True, immediate=True, timeout_ms=50)
    for ts, pkt in sniffer:
        try:
            rdot = dpkt.radiotap.Radiotap(pkt)
            ap = rdot.data.ssid.info.decode()
            if ap is not None:
            	print(ap + " "*(30-len(ap)) + mac2str(rdot.data.mgmt.bssid))
        except Exception:
            pass

sniff("wlan0")