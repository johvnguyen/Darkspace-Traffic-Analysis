from packet_types.packet_types import *

def get_packet_type(packet):
    if packet.haslayer('IP'):
        if is_udp_packet(packet):
            return 'UDP'
        elif is_tcp_packet(packet):
            return 'TCP'
        else:
            return 'UNKNOWN_IP_TYPE'
    elif is_icmp_packet(packet):
        return 'ICMP'
    elif is_arp_packet(packet):
        return 'ARP'
    else:
        return 'UNKNOWN'