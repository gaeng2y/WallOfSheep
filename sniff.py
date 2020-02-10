import pcap
import struct

eth_type_dict = {
    0x0800 : 'IP',
    0x0806 : 'ARP'
}

ip_proto_dict = {
    0x01 : 'ICMP',
    0x06 : 'TCP',
    0x11 : 'UDP'
}

def mac2str(mac):
    return ':'.join(map('{:02X}'.format, mac))

def ip2str(ip):
    return '.'.join(map('{:d}'.format, ip))

def u_ethernet(packet):
    return struct.unpack('! 6s 6s H', packet)

def u_ip(packet):
    return struct.unpack('!B B H H H B B H 4s 4s', packet)

def u_tcp(packet):
    return struct.unpack('!H H 4s 4s B B H H H', packet)

def sniff():
    sniffer = pcap.pcap(name=None, promisc=True, immediate=True, timeout_ms=50)

    for ts, pkt in sniffer:    
        dst_mac, src_mac, eth_type = u_ethernet(pkt[:14])            
        try:
            if eth_type_dict[eth_type] is 'IP':            
                vhl, tos, tlen, identification, ff, ttl, proto, cs, src_ip, dst_ip = u_ip(pkt[14:34])                        
                try:
                    if ip_proto_dict[proto] is 'TCP':                    
                        src_port, dst_port, seq, ack, tcp_len, *sth = u_tcp(pkt[34:54])
                        if src_port is 80 or dst_port is 80:
                            #print("http packet")
                            tmplen = (14 + (vhl&0x0F)*4 + (tcp_len>>4)*4)
                            if tmplen is not len(pkt):
                                #print(pkt[tmplen:])
                                return pkt[tmplen:], ip2str(src_ip)

                except KeyError:                
                    pass
        except KeyError:        
            pass