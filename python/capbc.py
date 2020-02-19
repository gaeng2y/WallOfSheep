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
    #bssid is key essid is value
    ap_dict = dict()
    for ts, pkt in sniffer:
        try:
            rdot = dpkt.radiotap.Radiotap(pkt)
            ap = rdot.data.ssid.info.decode()
            bssid = mac2str(rdot.data.mgmt.bssid)
            if ap is not None:
            	if bssid in ap_dict.keys():
            		pass
            	else:
            		ap_dict[bssid] = ap
            		aplist.aplist(conn, cur, bssid, ap)

        except Exception:
            pass


conn = pymysql.connect(host='localhost', user='jyp', password='wldbs11', db='wallofsheep', charset='utf8')
cur = conn.cursor()
sniff(sys.argv[1], conn, cur)
