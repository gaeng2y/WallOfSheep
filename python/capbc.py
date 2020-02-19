#!/usr/bin/python3

import pcap
import dpkt
import aplist
import sys
import pymysql

def mac2str(mac):
    return ':'.join(map('{:02X}'.format, mac))

def sniff(network_interface, conn, cur):
    sniffer = pcap.pcap(name=network_interface, promisc=True, immediate=True, timeout_ms=50)
    for ts, pkt in sniffer:
        try:
            rdot = dpkt.radiotap.Radiotap(pkt)
            ap = rdot.data.ssid.info.decode()
            if ap is not None:
            	aplist.aplist(conn, cur, mac2str(rdot.data.mgmt.bssid), ap)
            	print(ap + " "*(30-len(ap)) + mac2str(rdot.data.mgmt.bssid))
        except Exception:
            pass


conn = pymysql.connect(host='localhost', user='jyp', password='wldbs11', db='wallofsheep', charset='utf8')
cur = conn.cursor()
sniff(sys.argv[1], conn, cur)
