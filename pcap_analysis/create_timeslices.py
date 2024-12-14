from file_io_scripts.input import get_packets
from file_io_scripts.output import *
from pcap_processing.pcap_parsing import *
from pcap_processing.json_parsing import *
import threading
import itertools
import multiprocessing
import datetime
import ipaddress
import threading
import pandas as pd
from os import listdir
import csv
import numpy as np
import concurrent.futures
from concurrent.futures import ProcessPoolExecutor, as_completed
import argparse


class ThreadSafeInt:
    def __init__(self, initial_value=0):
        self.value = initial_value
        self.lock = threading.Lock()

    def increment_and_get(self):
        with self.lock:
            current_value = self.value
            self.value = current_value + 1
            return current_value

def process_pcaps(fname):
    #(fname, shared_int) = args
    #init_worker(shared_counter, lock)
    #print(f'Starting work on {fname}, the {files.index(fname)}th file')
    pcap_fpath = f'telescopesampleanon/pcapsanon/{fname}.pcap'
    json_fpath = f'telescopesampleanon/metadata/{fname}.json'
    csv_dir = 'csv_output/'

    #print(f'{files.index(fname)}th file loading packets')
    packets = get_packets(pcap_fpath)
    #print(f'{files.index(fname)}th file packets loaded!')

    #print(f'{files.index(fname)}th file loading jsons')
    jsons = parse_json(json_fpath)
    #print(f'{files.index(fname)}th file json loaded!')

    file = pcap_fpath.split('/')[-1]

    # I think file writers must be defined in the same scope -- cannot be closed by scope
    #csv_fname = make_csv_output_name(fname)
    #csv_fpath = f'{csv_dir}{csv_fname}'
    #csvfile = open(csv_fpath, 'w', newline = '')
    #csv_columns = output_columns # Defined in output.py
    #csv_writer = csv.DictWriter(csvfile, fieldnames = csv_columns)
    #csv_writer.writeheader()
    print(f'Writer initialized!')

    (timeslice_min, timeslice_max) = get_packet_interval(packets)
    timeslice_min = int(timeslice_min)
    timeslice_max = int(timeslice_max)

    timeslice_starts = range(timeslice_min, timeslice_max, 900)
    src_ips = get_unique_src_ips(packets)

    timeslice_df = make_empty_timeslice_df()
    metadata_df = make_empty_metadata_df()

    i = 0

    for timeslice in timeslice_starts:
        timeslice_str = datetime.datetime.fromtimestamp(timeslice).strftime('%c')
        src_ips = get_ips_in_timeslice(timeslice, packets)
        for src_ip in src_ips:
            src_timeslice_packets_with_metadata = get_timeslice_packets(timeslice, src_ip, packets, jsons)
            src_timeslice_packets = [packet for (packet, json) in src_timeslice_packets_with_metadata]
            if i % 7500 == 0:
                print(f'{fname} (the {files.index(fname)}the file) is on {(timeslice - timeslice_min) / 3600 * 60} min out of 60 min. This timeslice has {len(src_ips)} src ips.')
            i += 1

            # Save off pcaps in this timeslice to a file
            pcap_output_file = make_pcap_output_name(timeslice, src_ip)
            #save_timeslice_packets(src_timeslice_packets, pcap_output_file, file)

            # Save timeslice jsons here
            timeslice_jsons = [json for (packet, json) in src_timeslice_packets_with_metadata]
            #json_output_file = make_json_output_name(timeslice, src_ip)
            #save_timeslice_jsons(timeslice_jsons, json_output_file, file)

            # Index using an id value.

            row_idx = 0
            #with lock:
            #    row_idx = shared_int_ref.value
            #    shared_int_ref.value += 1

            metadata_dicts = make_metadata_dicts(row_idx, src_ip, src_timeslice_packets_with_metadata, timeslice)
            #save_metadata_to_df(metadata_dicts)
            #save_metadata_to_sql(row_idx, metadata_dict)
            for metadata_dict in metadata_dicts:
                save_metadata_to_df(metadata_dict, metadata_df)

            if src_timeslice_packets != []:
                # Calculate statistics for timeslice batch here
                min_packet_length = min([len(packet) for packet in src_timeslice_packets])
                max_packet_length = max([len(packet) for packet in src_timeslice_packets])
                avg_packet_length = sum([len(packet) for packet in src_timeslice_packets]) / len(src_timeslice_packets)
                std_dev_packet_length = np.std([len(packet) for packet in src_timeslice_packets], ddof = 0)
                (tcp_count, udp_count, icmp_count) = count_protocols(src_timeslice_packets)
                entropy = get_shannon_entropy(src_timeslice_packets)
                min_timestamp = min([packet.time for packet in src_timeslice_packets])
                max_timestamp = max([packet.time for packet in src_timeslice_packets])
                n_destinations = get_total_destinations(src_timeslice_packets)
                n_tcp_initiations = get_tcp_init_count(src_timeslice_packets)
                n_icmp_initiations = get_icmp_init_count(src_timeslice_packets)


                # Making dictionary/row
                row_data = {}
                row_data['timeslice'] = timeslice
                row_data['timeslice_str'] = timeslice_str
                row_data['src_ip'] = int(ipaddress.IPv4Address(src_ip))
                row_data['duration'] = float(max_timestamp - min_timestamp)
                row_data['min_packet_length'] = min_packet_length
                row_data['max_packet_length'] = max_packet_length
                row_data['avg_packet_length'] = avg_packet_length
                row_data['std_dev_packet_length'] = std_dev_packet_length
                row_data['n_packets'] = len(src_timeslice_packets)
                row_data['udp_proportion'] = udp_count / len(src_timeslice_packets)
                row_data['tcp_proportion'] = tcp_count / len(src_timeslice_packets)
                row_data['icmp_proportion'] = icmp_count / len(src_timeslice_packets)
                row_data['packet_length_shannon_entropy'] = float(entropy)
                row_data['n_destination_ips'] = n_destinations
                row_data['tcp_init_proportion'] = n_tcp_initiations / len(src_timeslice_packets)
                row_data['icmp_init_proportion'] = n_icmp_initiations / len(src_timeslice_packets)
                row_data['seconds_since_midnight'] = get_seconds_since_midnight(timeslice)
                row_data['isZMAP'] = getIsZMAP(src_timeslice_packets_with_metadata)
                row_data['isMasscan'] = getIsMasscan(src_timeslice_packets_with_metadata)
                row_data['isMirai'] = getIsMirai(src_timeslice_packets_with_metadata)
                row_data['isBogon'] = getIsBogon(src_timeslice_packets_with_metadata)
                row_data['KnownScanner'] = getKnownScanner(src_timeslice_packets_with_metadata)
                row_data['NetacqCountry'] = getNetacqCountry(src_timeslice_packets_with_metadata)
                row_data['MaxmindCountry'] = getMaxmindCountry(src_timeslice_packets_with_metadata)
                row_data['ASN'] = getASN(src_timeslice_packets_with_metadata)
                row_data['n_TTLs'] = get_number_ttls(src_timeslice_packets)
                row_data['n_src_ports'] = get_number_src_ports(src_timeslice_packets)
                row_data['n_dest_ports'] = get_number_dest_ports(src_timeslice_packets)
                row_data['heuristic_label'] = get_label(src_timeslice_packets_with_metadata)
                row_data['packet_volume'] = get_packet_volume(src_timeslice_packets)

                #save_timeslices_to_df(row_idx, row_data)
                timeslice_df.loc[len(timeslice_df)] = [
                    row_data['timeslice'], row_data['timeslice_str'],row_data['src_ip'], row_data['seconds_since_midnight'], row_data['duration'], \
                    row_data['min_packet_length'], row_data['max_packet_length'], row_data['avg_packet_length'], row_data['std_dev_packet_length'], row_data['packet_length_shannon_entropy'], \
                    row_data['udp_proportion'], row_data['tcp_proportion'], row_data['icmp_proportion'], row_data['tcp_init_proportion'], row_data['icmp_init_proportion'],  \
                    row_data['n_destination_ips'], row_data['n_packets'], row_data['isZMAP'], row_data['isMasscan'], row_data['isMirai'], \
                    row_data['isBogon'], row_data['KnownScanner'], row_data['NetacqCountry'], row_data['MaxmindCountry'], str(row_data['ASN']), row_data['n_TTLs'],
                    row_data['n_src_ports'], row_data['n_dest_ports'], row_data['heuristic_label'], row_data['packet_volume']
                ]
            else:
                pass

    timeslice_df.to_parquet(f'./db/timeslices/{fname}.parquet')
    metadata_df.to_parquet(f'./db/metadata/{fname}_meta.parquet')

    #csvfile.close()
    print(f'Finished working on file {fname}')

def print_hello(x):
    print(x)

    return

def init_worker(shared_int, lock):
    # This ensures that the shared integer and lock are available to each worker
    global shared_int_ref
    global lock_ref
    shared_int_ref = shared_int
    lock_ref = lock

def safe_process_pcaps(fname):
    try:
        process_pcaps(fname)
    except Exception as e:
        print(f'Found exception: {e} in file {fname}')
        raise e


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Take in number of threads")
    parser.add_argument(
        "--nthreads",
        type=int,
        default = 1,
        required=False,
        help="Number of threads to process pcaps"
    )

    args = parser.parse_args()
    n_threads = args.nthreads

    pcap_dir = 'telescopesampleanon/pcapsanon/'
    # Iterate through the list, loading each file for processing.
    files = listdir("./telescopesampleanon/pcapsanon")
    files = ['.'.join(file.split('.')[:-1]) for file in files]
    #files = files[:3]

    # Init new dbs here
    #init_dbs()
    thread_safe_int = ThreadSafeInt()

    #shared_int = multiprocessing.Value('i', 0)
    #process_pcaps(files[0], thread_safe_int)
    #args = [(f, shared_int) for f in files]
    #args = args[0]
    #with multiprocessing.Manager() as manager:
    #    shared_counter = manager.Value('i', 0, lock = True)
    shared_counter = multiprocessing.Value('i', 0, lock = False)
    lock = multiprocessing.Lock()
    #process_pcaps(files[0])
    #exit()
    '''
    with ProcessPoolExecutor(max_workers=64) as executor:
        try:
            #executor.map(process_pcaps, args)
            executor.map(print_hello, [thread_safe_int] *64)
        except Exception as e:
            print('Exception!')
            print(e)

    #convert_timeslice_db_to_parquet()
    '''
    '''
    threads = []
    semaphore = threading.Semaphore(64)
    for arg in args:
        thread = threading.Thread(target = process_pcaps, args = (arg, semaphore))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    '''
    #lock = multiprocessing.Lock()
    #with multiprocessing.Pool(processes = 1) as pool:
    #    pool.starmap(process_pcaps, [(f, shared_counter, lock) for f in files])

    #files = files[:2]

    #safe_process_pcaps('ucsd-nt.1660442400')
    #exit()

    with multiprocessing.Pool(processes=n_threads) as pool:
        pool.map(safe_process_pcaps, files)


    #convert_dataframes_to_parquet()

    print(f'Done processing pcap files!')

