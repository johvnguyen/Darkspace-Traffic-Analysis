from scapy.all import wrpcap
import pandas as pd
#import sqlite3
import os
import json
import threading
import ipaddress
import datetime

output_columns = ['timeslice', 
                  'src_ip', 
                  'seconds_since_midnight',
                  'duration',
                  'min_packet_length',
                  'max_packet_length',
                  'avg_packet_length',
                  'std_dev_packet_length',
                  'packet_length_shannon_entropy',
                  'udp_proportion',
                  'tcp_proportion',
                  'icmp_proportion',
                  'tcp_init_proportion',
                  'icmp_init_proportion',
                  'n_destination_ips',
                  'n_packets',
                  'isZMAP',
                  'isMasscan',
                  'isMirai',
                  'isBogon',
                  'KnownScanner',
                  'NetacqCountry',
                  'MaxmindCountry',
                  'ASN']

def make_csv_output_name(input_name):
    return ''.join([input_name, '.csv'])

def make_output_name(input_fname):
    input_parts = input_fname.split('.')
    output_fname = ''.join([input_parts[0], input_parts[1], '.pcap'])

    return output_fname

def make_pcap_output_name(timestamp, src_ip):
    #src_ip = src_ip.replace('.', '_')
    timestamp = str(timestamp) + '_'
    output_fname = ''.join([timestamp, src_ip, '.pcap'])

    return output_fname

def save_timeslice_packets(src_timeslice_packets, pcap_output_file, file):
    input_parts = file.split('.')
    output_subdir = f'pcap_output/{input_parts[0]}.{input_parts[1]}/'

    if not os.path.exists(output_subdir):
        os.makedirs(output_subdir)

    output_fpath = f'{output_subdir}{pcap_output_file}'

    #print(f'Saving pcaps to: {output_fpath}')

    wrpcap(output_fpath, src_timeslice_packets)

    return
    
def make_json_output_name(timestamp, src_ip):
    #src_ip = src_ip.replace('.', '_')
    timestamp = str(timestamp) + '_'
    output_fname = ''.join([timestamp, src_ip, '.json'])

    return output_fname

def save_timeslice_jsons(src_timeslice_jsons, json_output_file, file):
    input_parts = file.split('.')
    output_subdir = f'json_output/{input_parts[0]}.{input_parts[1]}/'

    if not os.path.exists(output_subdir):
        os.makedirs(output_subdir)

    output_fpath = f'{output_subdir}{json_output_file}'

    with open(output_fpath, 'w') as json_file:
        json.dump(src_timeslice_jsons, json_file, indent=4)

    return

def init_dbs():
    if os.path.exists("./db/metadata.db"):
        os.remove("./db/metadata.db")
    if os.path.exists("./db/timeslices.db"):
        os.remove("./db/timeslices.db")
    if os.path.exists("./db/timeslices.parquet"):
        os.remove("./db/timeslices.parquet")


    init_metadata_db()
    init_timeslice_db()

    return
    

def init_metadata_db():
    metadata_db_path = "./db/metadata.db"
    conn = sqlite3.connect(metadata_db_path)
    cursor = conn.cursor()

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS metadata (
    id INTEGER PRIMARY KEY,
    json_metadata TEXT,
    pcaps BLOB
    )
    ''')

    conn.commit()
    conn.close()

    return

def init_timeslice_db():
    timeslice_db_path = "./db/timeslices.db"
    conn = sqlite3.connect(timeslice_db_path)
    cursor = conn.cursor()

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS timeslices (
    id INTEGER PRIMARY KEY,
    timeslice INTEGER,
    src_ip TEXT,
    seconds_since_midnight INTEGER,
    duration INTEGER,
    min_packet_length INTEGER,
    max_packet_length INTEGER,
    avg_packet_length REAL,
    std_dev_packet_length REAL,
    packet_length_shannon_entropy REAL,
    udp_proportion REAL,
    tcp_proportion REAL,
    icmp_proportion REAL,
    tcp_init_proportion REAL,
    icmp_init_proportion REAL,
    n_destination_ips INTEGER,
    n_packets INTEGER,
    isZMAP INTEGER,
    isMasscan INTEGER,
    isMirai INTEGER,
    isBogon INTEGER,
    KnownScannerEnum INTEGER,
    NetacqCountry TEXT,
    MaxmindCountry TEXT,
    ASN INTEGER
    )
    ''')

    conn.commit()
    conn.close()

    return

def save_metadata_to_sql(idx, metadata_dict):
    db_path = "./db/metadata.db"
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Cannot autoincrement id because we need to maintain consistency between metadata.db and timeslices.db
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS metadata (
    id INTEGER PRIMARY KEY,
    json_metadata TEXT,
    pcaps BLOB
    )
    ''')

    conn.commit()

    cursor.execute('''
    INSERT INTO metadata (id, json_metadata, pcaps)
    VALUES(?, ?, ?)
    ''', (idx, metadata_dict['jsons'], metadata_dict['pcaps']))

    conn.commit()
    conn.close()

    return

def save_timeslice_to_sql(idx, timeslice_dict):
    db_path = "./db/timeslices.db"

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Cannot autoincrement id because we need to maintain consistency between metadata.db and timeslices.db
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS timeslices (
    id INTEGER PRIMARY KEY,
    timeslice INTEGER,
    src_ip TEXT,
    seconds_since_midnight INTEGER,
    duration REAL,
    min_packet_length INTEGER,
    max_packet_length INTEGER,
    avg_packet_length REAL,
    std_dev_packet_length REAL,
    packet_length_shannon_entropy REAL,
    udp_proportion REAL,
    tcp_proportion REAL,
    icmp_proportion REAL,
    tcp_init_proportion REAL,
    icmp_init_proportion REAL,
    n_destination_ips INTEGER,
    n_packets INTEGER,
    isZMAP BOOLEAN,
    isMasscan BOOLEAN,
    isMirai BOOLEAN,
    isBogon BOOLEAN,
    KnownScannerEnum INTEGER,
    NetacqCountry TEXT,
    MaxmindCountry TEXT,
    ASN INTEGER
    )
    ''')
    conn.commit()

    cursor.execute('''
    INSERT INTO timeslices (id, timeslice, src_ip, seconds_since_midnight, duration,
        min_packet_length, max_packet_length, avg_packet_length, std_dev_packet_length, packet_length_shannon_entropy,
        udp_proportion, tcp_proportion, icmp_proportion, tcp_init_proportion, icmp_init_proportion,
        n_destination_ips, n_packets, isZMAP, isMasscan, isMirai, 
        isBogon, KnownScannerEnum, NetacqCountry, MaxmindCountry, ASN)
    VALUES(?, ?, ?, ?, ?,
           ?, ?, ?, ?, ?,
           ?, ?, ?, ?, ?,
           ?, ?, ?, ?, ?,
           ?, ?, ?, ?, ?
    )
    ''', (idx, timeslice_dict['timeslice'], timeslice_dict['src_ip'], timeslice_dict['seconds_since_midnight'], timeslice_dict['duration'],
          timeslice_dict['min_packet_length'], timeslice_dict['max_packet_length'], timeslice_dict['avg_packet_length'], timeslice_dict['std_dev_packet_length'], timeslice_dict['packet_length_shannon_entropy'],
          timeslice_dict['udp_proportion'], timeslice_dict['tcp_proportion'], timeslice_dict['icmp_proportion'], timeslice_dict['tcp_init_proportion'], timeslice_dict['icmp_init_proportion'], 
          timeslice_dict['n_destination_ips'], timeslice_dict['n_packets'], timeslice_dict['isZMAP'], timeslice_dict['isMasscan'], timeslice_dict['isMirai'], 
          timeslice_dict['isBogon'], timeslice_dict['KnownScanner'], timeslice_dict['NetacqCountry'], timeslice_dict['MaxmindCountry'], str(timeslice_dict['ASN'])))

    conn.commit()
    conn.close()

    return

def convert_timeslice_db_to_parquet():
    timeslice_db_path = "./db/timeslices.db"
    output_file = "./db/timeslices.parquet"

    conn = sqlite3.connect(timeslice_db_path)
    query = "SELECT * FROM timeslices"
    df = pd.read_sql_query(query, conn)

    df.to_parquet(output_file, engine = "pyarrow", index = False)
    
    conn.close()

    return

def make_metadata_dicts(row_idx, src_ip, src_timeslice_packets_with_metadata, timeslice):    
    metadata_dicts = [make_metadata_dict(row_idx, src_ip, data_and_metadata, timeslice) for data_and_metadata in src_timeslice_packets_with_metadata]

    return metadata_dicts

def make_metadata_dict(row_idx, src_ip, data_and_metadata, timeslice):
    timeslice_str = datetime.datetime.fromtimestamp(timeslice).strftime('%c')
    (data, metadata) = data_and_metadata

    metadata_dict = {}
    metadata_dict['timeslice'] = timeslice
    metadata_dict['timeslice_str'] = timeslice_str
    metadata_dict['source_ip'] = int(ipaddress.IPv4Address(src_ip))
    metadata_dict['src_port'] = get_src_port(data)
    metadata_dict['dest_ip'] = data['IP'].dst
    metadata_dict['dest_port'] = get_dest_port(data)
    metadata_dict['protocol_type'] = get_packet_type(data)
    metadata_dict['is_init'] = is_initiation_packet(data)
    metadata_dict['packet_length'] = len(data)
    metadata_dict['ttl'] = data['IP'].ttl
    metadata_dict['IsZmap'] = metadata['IsZmap']
    metadata_dict['IsMasscan'] = metadata['IsMasscan']
    metadata_dict['IsMirai'] = metadata['IsMirai']
    metadata_dict['IsBogon'] = metadata['IsBogon']
    metadata_dict['SrcASN'] = str(metadata['SrcASN'])
    metadata_dict['NetacqCountry'] = metadata['NetacqCountry']
    metadata_dict['MaxmindCountry'] = metadata['MaxmindCountry']
    metadata_dict['KnownScanner'] = metadata['KnownScanner']

    metadata_dict['timestamp'] = datetime.datetime.fromtimestamp(int(data.time)).strftime('%c')

    return metadata_dict

def get_src_port(packet):
    if packet.haslayer('TCP'):
        return int(packet['TCP'].sport)
    elif packet.haslayer('UDP'):
        return int(packet['UDP'].sport)
    else:
        return -1

def get_dest_port(packet):
    if packet.haslayer('TCP'):
        return int(packet['TCP'].dport)
    elif packet.haslayer('UDP'):
        return int(packet['UDP'].dport)
    else:
        return -1

def get_packet_type(packet):
    if packet.haslayer('TCP'):
        return 'TCP'
    elif packet.haslayer('UDP'):
        return 'UDP'
    elif packet.haslayer('ICMP'):
        return 'ICMP'
    else:
        return 'Unknown'

def is_initiation_packet(packet):
    if packet.haslayer('TCP'):
        if packet['TCP'].flags == "S":
            return True
    elif packet.haslayer('ICMP'):
        if packet['ICMP'].type == 8:
            return True
    else:
        return False




def save_metadata_to_df(metadata_dict, metadata_df):
    
    metadata_df.loc[len(metadata_df)] = [
                metadata_dict['timeslice'],
                metadata_dict['timeslice_str'],
                metadata_dict['source_ip'],
                metadata_dict['src_port'],
                metadata_dict['dest_ip'],
                metadata_dict['dest_port'],
                metadata_dict['protocol_type'],
                metadata_dict['is_init'],
                metadata_dict['packet_length'],
                metadata_dict['ttl'],
                metadata_dict['IsZmap'],
                metadata_dict['IsMasscan'],
                metadata_dict['IsMirai'],
                metadata_dict['IsBogon'],
                metadata_dict['SrcASN'],
                metadata_dict['NetacqCountry'],
                metadata_dict['MaxmindCountry'],
                metadata_dict['KnownScanner'],
                metadata_dict['timestamp']
                ]

    return

def save_timeslices_to_df(idx, timeslice_dict):
    with timeslice_lock:
        timeslice_df.loc[len(timeslice_df)] = [
            timeslice_dict['timeslice'], timeslice_dict['src_ip'], timeslice_dict['seconds_since_midnight'], timeslice_dict['duration'], \
            timeslice_dict['min_packet_length'], timeslice_dict['max_packet_length'], timeslice_dict['avg_packet_length'], timeslice_dict['std_dev_packet_length'], timeslice_dict['packet_length_shannon_entropy'], \
            timeslice_dict['udp_proportion'], timeslice_dict['tcp_proportion'], timeslice_dict['icmp_proportion'], timeslice_dict['tcp_init_proportion'], timeslice_dict['icmp_init_proportion'],  \
            timeslice_dict['n_destination_ips'], timeslice_dict['n_packets'], timeslice_dict['isZMAP'], timeslice_dict['isMasscan'], timeslice_dict['isMirai'], \
            timeslice_dict['isBogon'], timeslice_dict['KnownScanner'], timeslice_dict['NetacqCountry'], timeslice_dict['MaxmindCountry'], str(timeslice_dict['ASN'])
            ]

    return
    

def convert_dataframes_to_parquet():
    if os.path.exists("./db/metadata.parquet"):
        os.remove("./db/metadata.parquet")
    if os.path.exists("./db/timeslices.parquet"):
        os.remove("./db/timeslices.parquet")

    metadata_df.to_parquet('./db/metadata.parquet')
    timeslice_df.to_parquet("./db/timeslices.parquet")

    return

def make_empty_timeslice_df():
    return pd.DataFrame({
                        'timeslice' : pd.Series(dtype = 'int'), 
                        'timeslice_str' : pd.Series(dtype = 'str'),
                        'src_ip' : pd.Series(dtype = 'int'), 
                        'seconds_since_midnight' : pd.Series(dtype = 'int'),
                        'duration' : pd.Series(dtype = 'float'),
                        'min_packet_length' : pd.Series(dtype = 'int'),
                        'max_packet_length' : pd.Series(dtype = 'int'),
                        'avg_packet_length' : pd.Series(dtype = 'float'),
                        'std_dev_packet_length' : pd.Series(dtype = 'float'),
                        'packet_length_shannon_entropy' : pd.Series(dtype = 'float'),
                        'udp_proportion' : pd.Series(dtype = 'float'),
                        'tcp_proportion' : pd.Series(dtype = 'float'),
                        'icmp_proportion' : pd.Series(dtype = 'float'),
                        'tcp_init_proportion' : pd.Series(dtype = 'float'),
                        'icmp_init_proportion' : pd.Series(dtype = 'float'),
                        'n_destination_ips' : pd.Series(dtype = 'int'),
                        'n_packets' : pd.Series(dtype = 'int'),
                        'isZMAP' : pd.Series(dtype = 'bool'),
                        'isMasscan' : pd.Series(dtype = 'bool'),
                        'isMirai' : pd.Series(dtype = 'bool'),
                        'isBogon' : pd.Series(dtype = 'bool'),
                        'KnownScanner' : pd.Series(dtype = 'str'),
                        'NetacqCountry' : pd.Series(dtype = 'str'),
                        'MaxmindCountry' : pd.Series(dtype = 'str'),
                        'ASN' : pd.Series(dtype = 'str'),
                        'n_TTLs' : pd.Series(dtype = 'int'),
                        'n_src_ports' : pd.Series(dtype = 'int'),
                        'n_dest_ports' : pd.Series(dtype = 'int'),
                        'heuristic_label' : pd.Series(dtype = 'int'),
                        'packet_volume' : pd.Series(dtype = 'int')
                        })

def make_empty_metadata_df():
    return pd.DataFrame({
                    'timeslice' : pd.Series(dtype = 'int'),
                    'timeslice_str' : pd.Series(dtype = 'str'),
                    'source_ip' : pd.Series(dtype = 'int'), 
                    'src_port' : pd.Series(dtype = 'int'),
                    'dest_ip' : pd.Series(dtype = 'str'),
                    'dest_port' : pd.Series(dtype = 'int'),
                    'protocol_type' : pd.Series(dtype = 'str'),
                    'is_init' : pd.Series(dtype = 'bool'),
                    'packet_length' : pd.Series(dtype = 'int'),
                    'ttl' : pd.Series(dtype = 'int'),
                    'IsZmap' : pd.Series(dtype = 'bool'),
                    'IsMasscan' : pd.Series(dtype = 'bool'),
                    'IsMirai' : pd.Series(dtype = 'bool'),
                    'IsBogon' : pd.Series(dtype = 'bool'),
                    'SrcASN' : pd.Series(dtype = 'str'),
                    'NetacqCountry' : pd.Series(dtype = 'str'),
                    'MaxmindCountry' : pd.Series(dtype = 'str'),
                    'KnownScanner' : pd.Series(dtype = 'str'),
                    'timestamp' : pd.Series(dtype = 'str')
                    })

def get_number_src_ports(src_timeslice_packets):
    src_ports = [get_src_port(packet) for packet in src_timeslice_packets]
    src_ports = [port for port in src_ports if port != -1]

    return len(src_ports)

def get_number_dest_ports(src_timeslice_packets):
    dest_ports = [get_dest_port(packet) for packet in src_timeslice_packets]
    dest_ports = [port for port in dest_ports if port != -1]

    return len(dest_ports)

'''
timeslice_lock = threading.Lock()
metadata_lock = threading.Lock()
metadata_df = pd.DataFrame({'timeslice_id' : pd.Series(dtype = 'int'), 
                            'source_ip' : pd.Series(dtype = 'str'), 
                            'dest_ip' : pd.Series(dtype = 'str'),
                            'timestamp' : pd.Series(dtype = 'int'),
                            'protocol_type' : pd.Series(dtype = 'str'),
                            'is_init' : pd.Series(dtype = 'bool'),
                            'packet_length' : pd.Series(dtype = 'int'),
                            'ttl' : pd.Series(dtype = 'int'),
                            'IsZmap' : pd.Series(dtype = 'bool'),
                            'IsMasscan' : pd.Series(dtype = 'bool'),
                            'IsMirai' : pd.Series(dtype = 'bool'),
                            'IsBogon' : pd.Series(dtype = 'bool'),
                            'SrcASN' : pd.Series(dtype = 'str'),
                            'NetacqCountry' : pd.Series(dtype = 'str'),
                            'MaxmindCountry' : pd.Series(dtype = 'str'),
                            'KnownScanner' : pd.Series(dtype = 'str')
                            })

timeslice_df = pd.DataFrame({'index' : pd.Series(dtype = 'int'), 
                        'timeslice' : pd.Series(dtype = 'int'), 
                        'src_ip' : pd.Series(dtype = 'str'), 
                        'seconds_since_midnight' : pd.Series(dtype = 'int'),
                        'duration' : pd.Series(dtype = 'float'),
                        'min_packet_length' : pd.Series(dtype = 'int'),
                        'max_packet_length' : pd.Series(dtype = 'int'),
                        'avg_packet_length' : pd.Series(dtype = 'float'),
                        'std_dev_packet_length' : pd.Series(dtype = 'float'),
                        'packet_length_shannon_entropy' : pd.Series(dtype = 'float'),
                        'udp_proportion' : pd.Series(dtype = 'float'),
                        'tcp_proportion' : pd.Series(dtype = 'float'),
                        'icmp_proportion' : pd.Series(dtype = 'float'),
                        'tcp_init_proportion' : pd.Series(dtype = 'float'),
                        'icmp_init_proportion' : pd.Series(dtype = 'float'),
                        'n_destination_ips' : pd.Series(dtype = 'int'),
                        'n_packets' : pd.Series(dtype = 'int'),
                        'isZMAP' : pd.Series(dtype = 'bool'),
                        'isMasscan' : pd.Series(dtype = 'bool'),
                        'isMirai' : pd.Series(dtype = 'bool'),
                        'isBogon' : pd.Series(dtype = 'bool'),
                        'KnownScannerEnum' : pd.Series(dtype = 'int'),
                        'NetacqCountry' : pd.Series(dtype = 'str'),
                        'MaxmindCountry' : pd.Series(dtype = 'str'),
                        'ASN' : pd.Series(dtype = 'str')})
'''
