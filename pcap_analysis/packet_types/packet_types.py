def is_udp_packet(packet):
    return packet.haslayer('UDP')

def is_tcp_packet(packet):
    return packet.haslayer('TCP')

def is_icmp_packet(packet):
    return packet.haslayer('ICMP')
    
def is_arp_packet(packet):
    return packet.haslayer('ARP')
