from scapy.all import rdpcap

def get_packets(filepath):
    packets = rdpcap(filepath)

    return packets