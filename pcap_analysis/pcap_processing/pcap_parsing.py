import numpy as np
from scipy.stats import entropy
from datetime import datetime


def get_unique_src_ips(packets):
    src_ips = set()

    for packet in packets:
        if packet.haslayer('IP'):
            src_ips.add(packet['IP'].src)

    return src_ips

def get_timeslice_packets(timeslice_center, src_ip, packets, jsons):
    desired_packets = [(packet, json) for (packet, json) in zip(packets, jsons) if is_matching_packet(timeslice_center, src_ip, packet)]

    return desired_packets

def is_matching_packet(timeslice_center, src_ip, packet):
    timestamp = float(packet.time)
    if timestamp_in_timeslice(timeslice_center, timestamp):
            if packet.haslayer('IP'):
                if packet['IP'].src == src_ip:
                    return True
    
    return False

def timestamp_in_timeslice(timeslice_center, timestamp):
    return (timestamp >= timeslice_center) and (timestamp <= timeslice_center + 900)

def get_max_packet_len(packets):
    max_packet_len = -1

    for packet in packets:
        packet_length = len(packet)

        if packet_length > max_packet_len:
            max_packet_len = packet_length

    return max_packet_len

def get_ips_in_timeslice(timeslice, packets):
    ip_packets = [packet for packet in packets if packet.haslayer('IP')]
    packets_in_timeslice = [packet for packet in ip_packets if timestamp_in_timeslice(timeslice, float(packet.time))]
    src_ips = list(set([packet['IP'].src for packet in packets_in_timeslice]))
    #print(f'We have {len(src_ips)} ips in this timeslice')

    return src_ips

def get_packet_interval(packets):
    timestamps = [float(packet.time) for packet in packets]

    return (min(timestamps), max(timestamps))

def count_protocols(packets):
    tcp_count = len([packet for packet in packets if packet.haslayer('TCP')])
    udp_count = len([packet for packet in packets if packet.haslayer('UDP')])
    icmp_count = len([packet for packet in packets if packet.haslayer('ICMP')])

    return (tcp_count, udp_count, icmp_count)

def get_shannon_entropy(packets):
    lengths = np.array([len(packet) for packet in packets])
    _, counts = np.unique(lengths, return_counts = True)
    probs = counts / counts.sum()

    return entropy(probs, base = 2)

def get_total_destinations(packets):
    ip_packets = [packet for packet in packets if packet.haslayer('IP')]
    dest_ips = [packet['IP'].dst for packet in ip_packets]
    dest_ips = set(dest_ips)

    return len(dest_ips)

def get_tcp_init_count(packets):
    ip_packets = [packet for packet in packets if packet.haslayer('IP')]
    tcp_packets = [packet for packet in ip_packets if packet.haslayer('TCP')]
    tcp_init_packets = [packet for packet in tcp_packets if packet['TCP'].flags == 'S']

    return len(tcp_init_packets)

def get_icmp_init_count(packets):
    ip_packets = [packet for packet in packets if packet.haslayer('IP')]
    icmp_packets = [packet for packet in ip_packets if packet.haslayer('ICMP')]
    icmp_init_packets = [packet for packet in icmp_packets if packet['ICMP'] == 8]

    return len(icmp_init_packets)

def get_seconds_since_midnight(timeslice):
    dt = datetime.fromtimestamp(timeslice)
    seconds_since_midnight = dt.hour * 3600 + dt.minute * 60 + dt.second

    return seconds_since_midnight

def get_number_ttls(src_timeslice_packets):
    ttls = [packet['IP'].ttl for packet in src_timeslice_packets]
    return len(set(ttls))

def get_packet_volume(src_timeslice_packets):
    return sum([len(packet) for packet in src_timeslice_packets])
