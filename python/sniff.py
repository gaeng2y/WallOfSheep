import pcap
import dpkt

def mac2str(mac):
    return ':'.join(map('{:02X}'.format, mac))

def ip2str(ip):
    return '.'.join(map('{:d}'.format, ip))

def sniff(network_interface):
    sniffer = pcap.pcap(name=network_interface, promisc=True, immediate=True, timeout_ms=50)
    for ts, pkt in sniffer:
        try:
            rdot = dpkt.radiotap.Radiotap(pkt)
            logical_link_control = dpkt.llc.LLC(rdot.data.data_frame.data)
            if logical_link_control.data.data.dport is 80:
                return logical_link_control.data.data.data, ip2str(logical_link_control.data.src), mac2str(rdot.data.data_frame.src), 'HTTP'
        except Exception:
            pass

