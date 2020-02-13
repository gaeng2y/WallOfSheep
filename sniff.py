import pcap
import dpkt

def sniff(network_interface):
    sniffer = pcap.pcap(name=network_interface, promisc=True, immediate=True, timeout_ms=50)
    for ts, pkt in sniffer:
        try:
            rdot = dpkt.radiotap.Radiotap(pkt)
            logical_link_control = dpkt.llc.LLC(rdot.data.data_frame.data)
            if logical_link_control.data.data.dport is 80 or logical_link_control.data.data.sport is 80:
                return logical_link_control.data.data
        except Exception:
            pass

#sniff("wlan0")
