#!/usr/bin/env python3

import os
import multiprocessing

# Set environment variables for threading
# this needs to be before the rest of the imports
default_n_threads = min(multiprocessing.cpu_count(), 64)
os.environ['OPENBLAS_NUM_THREADS'] = f"{default_n_threads}"
os.environ['MKL_NUM_THREADS'] = f"{default_n_threads}"
os.environ['OMP_NUM_THREADS'] = f"{default_n_threads}"

import re
import datetime
import logging
import sys
import argparse
import socket
import struct

import pandas as pd
import numpy as np

from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.manifold import TSNE
from sklearn.cluster import KMeans, AgglomerativeClustering, HDBSCAN
from umap import UMAP

from anyio.lowlevel import RunVar
from anyio import CapacityLimiter

from pydantic import BaseModel
from typing import Literal, List, Optional, Any
from functools import lru_cache

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse


DURATION_REGEX = re.compile(r'([0-9]*(\.[0-9]*)?)([a-z]+)')

# Initialize FastAPI app
app = FastAPI()

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins (for development)
    allow_credentials=True,
    allow_methods=["*"],  # Allow all HTTP methods
    allow_headers=["*"],  # Allow all headers
)

literals = {
    'tsne': 't-SNE',
    'umap': 'UMAP',
    'pca': 'PCA',
    'kmeans': 'KMeans',
    'agglo': 'Agglo',
    'known': 'Heuristic Labels',
    'hdbscan': 'HDBSCAN',
    'none': 'None',
    'timeslice': 'Timestamp',
    'seconds_since_midnight': 'Seconds Since Midnight',
    'duration': 'Duration',
    'tcp_proportion': 'TCP Proportion',
    'udp_proportion': 'UDP Proportion',
    'icmp_proportion': 'ICMP Proportion',
    'tcp_init_proportion': 'TCP Initiation Proportion',
    'icmp_init_proportion': 'ICMP Initiation Proportion',
    'max_packet_length': 'Packet Length: Max',
    'avg_packet_length': 'Packet Length: Average',
    'min_packet_length': 'Packet Length: Min',
    'packet_length_shannon_entropy': 'Packet Length: Entropy',
    'std_dev_packet_length': 'Packet Length: STD',
    'n_TTLs': 'Distinct TTLs',
    'ASN': 'Autonomous System',
    'n_packets': 'Number of Packets',
    'n_destination_ips': 'Number of Destination IPs'
}

always_drop = [
    'src_ip',
    'isZMAP',
    'isMasscan',
    'isMirai',
    'isBogon',
    'KnownScanner',
    'NetacqCountry',
    'MaxmindCountry',
    'ASN',
    'index',
    'date',
    'heuristic_label'
]

heuristic_labels = [
    'Unknown',
    'ZMAP',
    'Masscan',
    'Mirai',
    'Bogon',
    'Known Scanner',
    ]

class TimesliceDataFormat(BaseModel):
    length: int
    reduced_x: List[float]
    reduced_y: List[float]
    labels: List[int]
    timestamp: List[int]
    date: List[str]
    src_ip: List[str]
    src_ip_int: List[int]
    n_src_ports: List[int]
    n_dest_ports: List[int]
    seconds_since_midnight: List[int]
    duration: List[float]
    min_packet_length: List[int]
    max_packet_length: List[int]
    avg_packet_length: List[float]
    std_dev_packet_length: List[float]
    packet_length_shannon_entropy: List[float]
    udp_proportion: List[float]
    tcp_proportion: List[float]
    icmp_proportion: List[float]
    tcp_init_proportion: List[float]
    icmp_init_proportion: List[float]
    n_destination_ips: List[int]
    n_packets: List[int]
    n_TTLs: List[int]
    packet_volume: List[int]
    id: List[int]
    KnownScanner: List[str]
    NetacqCountry: List[str]
    MaxmindCountry: List[str]
    ASN: List[Any]

class MetadataFormat(BaseModel):
    timestamp: List[int]
    date: List[str]
    src_ip: List[str]
    src_port: List[int]
    dest_ip: List[str]
    dest_port: List[int]
    protocol_type: List[str]
    is_init: List[bool]
    packet_length: List[int]
    ttl: List[int]
    SrcASN: List[Any]
    n_packets: List[int]
    duration: List[float]
    id: List[int]
    KnownScanner: List[str]
    NetacqCountry: List[str]
    MaxmindCountry: List[str]
    # HueristicLabel: List[str]
    length: int

class GetTransformationRequest(BaseModel):
    reduction: Literal['tsne', 'umap', 'pca', 'none']
    clustering: Literal['kmeans', 'hdbscan', 'agglo', 'known', 'none']
    reduction_parameter: float
    clustering_parameter: int
    max_samples: int
    percent_samples: int
    min_timeslice: str
    off_timeslice: str
    min_duration: Optional[int]
    off_duration: Optional[int]
    features: List[Literal[
        'timeslice', 'src_ip_int', 'seconds_since_midnight', 'duration', 'min_packet_length', 'max_packet_length', 'avg_packet_length', 'std_dev_packet_length', 'packet_length_shannon_entropy', 'udp_proportion', 'tcp_proportion', 'icmp_proportion', 'tcp_init_proportion', 'icmp_init_proportion', 'n_destination_ips', 'n_packets', 'n_TTLs', 'n_src_ports', 'n_dest_ports', 'packet_volume', 'ASN', 'only_unknowns', 'min2packets']]

class GetTransformationResponse(BaseModel):
    error: Optional[str] = None
    data: Optional[TimesliceDataFormat] = None
    x_label: str
    y_label: str
    clustering: str
    reduction: str
    title: str
    possible_labels: List[str]

class GetMetadataRequest(BaseModel):
    ids: List[int]

class GetMetadataResponse(BaseModel):
    data: MetadataFormat

def make_error(error: str) -> GetTransformationResponse:
    return {
        'error': error,
        'x_label': '',
        'y_label': '',
        'title': '',
        'clustering': '',
        'reduction': '',
        'possible_labels': []
    }


def clean_payload(payload: GetTransformationRequest) -> GetTransformationRequest:
    if payload.max_samples == 0:
        raise(ValueError('max_samples must not be 0'))

    if payload.percent_samples <= 0:
        raise(ValueError('percent_samples must be greater than 0'))

    if payload.percent_samples > 100:
        raise(ValueError('percent_samples must be less than 100'))

    if not payload.min_timeslice:
        raise(ValueError('first timeslice must not be empty'))

    if not payload.off_timeslice:
        raise(ValueError('timeslice length must not be empty'))

    if len(payload.features) < 2:
        raise(ValueError('must select at least 2 features'))

    if payload.max_samples < 0:
        payload.max_samples = -1

    if payload.reduction == 'none' or payload.reduction == 'pca':
        payload.reduction_parameter = 0

    if payload.clustering == 'none' or payload.clustering == 'known':
        payload.clustering_parameter = 0

    payload.min_duration = parse_duration(payload.min_timeslice)
    payload.off_duration = parse_duration(payload.off_timeslice)

    return payload

@lru_cache()
def compute(
        reduction,
        clustering,
        max_samples,
        percent_samples,
        reduction_parameter,
        clustering_parameter,
        min_timeslice,
        off_timeslice,
        min_duration,
        off_duration,
        features
        ):
    # Perform reduction and clustering
    sampled, reduced = compute_reduction(reduction, reduction_parameter, min_duration, off_duration, max_samples, percent_samples, features)
    labels, possible_labels = compute_clustering(sampled, reduced, clustering, clustering_parameter)

    samples_str = max_samples
    if max_samples < 0:
        samples_str = 'all'

    title = f'{literals[reduction]} by {literals[clustering]} from {min_timeslice}:{off_timeslice} with {samples_str} samples'

    x_label = f'{literals[reduction]} Component 0'
    y_label = f'{literals[reduction]} Component 1'

    if reduction == 'none':
        x_label = literals[features[0]]
        y_label = literals[features[1]]

    response_data = {
        'data': {
            'length': reduced.shape[0],
            'reduced_x': reduced[:, 0].tolist(),
            'reduced_y': reduced[:, 1].tolist(),
            'timestamp': (sampled['timeslice'] - first_timeslice).tolist(),
            'date': sampled['date'].tolist(),
            'src_ip': sampled['src_ip'].tolist(),
            'src_ip_int': sampled['src_ip_int'].tolist(),
            'duration': sampled['duration'].tolist(),
            'seconds_since_midnight': sampled['seconds_since_midnight'].tolist(),
            'min_packet_length': sampled['min_packet_length'].tolist(),
            'max_packet_length': sampled['max_packet_length'].tolist(),
            'avg_packet_length': sampled['avg_packet_length'].tolist(),
            'std_dev_packet_length': sampled['std_dev_packet_length'].tolist(),
            'packet_length_shannon_entropy': sampled['packet_length_shannon_entropy'].tolist(),
            'udp_proportion': sampled['udp_proportion'].tolist(),
            'tcp_proportion': sampled['tcp_proportion'].tolist(),
            'icmp_proportion': sampled['icmp_proportion'].tolist(),
            'tcp_init_proportion': sampled['tcp_init_proportion'].tolist(),
            'icmp_init_proportion': sampled['icmp_init_proportion'].tolist(),
            'n_destination_ips': sampled['n_destination_ips'].tolist(),
            'n_packets': sampled['n_packets'].tolist(),
            'n_TTLs': sampled['n_TTLs'].tolist(),
            'n_src_ports': sampled['n_src_ports'].tolist(),
            'n_dest_ports': sampled['n_dest_ports'].tolist(),
            'packet_volume': sampled['packet_volume'].tolist(),
            'KnownScanner': sampled['KnownScanner'].tolist(),
            'NetacqCountry': sampled['NetacqCountry'].tolist(),
            'MaxmindCountry': sampled['MaxmindCountry'].tolist(),
            'id': sampled['index'].tolist(),
            'ASN': sampled['ASN'].tolist(),
            'labels': labels,  # Add the clustering labels
        },
        'title': title,
        'x_label': x_label,
        'y_label': y_label,
        'clustering': clustering,
        'reduction': reduction,
        'possible_labels': possible_labels # The possible labels (clusters)
    }

    return response_data


@lru_cache()
def compute_reduction(reduction, reduction_parameter, min_duration, off_duration, max_samples, percent_samples, features):
    df = timeslice_df.copy()

    max_duration = off_duration

    if 'only_unknowns' in features:
        df = df.loc[df['heuristic_label'] == 0]

    if 'min2packets' in features:
        df = df.loc[df['n_packets'] >= 2]

    if min_duration >= 0:
        min_duration += first_timeslice
        df = df.loc[df['timeslice'] >= min_duration]
        if df.shape[0] == 0:
            raise ValueError(f'the first timeslice is past the last timeslice "{last_timeslice-first_timeslice}", try reducing the first timeslice')

    if max_duration >= 0:
        if min_duration >= 0:
            max_duration += min_duration
        else:
            max_duration += first_timeslice

        df = df.loc[df['timeslice'] < max_duration]

        if df.shape[0] == 0:
            raise ValueError(f'the offset timeslice removes all timeslices, try increasing the offset')

    X_sampled = df
    if percent_samples != 100:
        logger.info(f'percent samples: {percent_samples}')
        X_sampled = X_sampled.sample(n=X_sampled.shape[0] * percent_samples // 100, random_state=42)

    if max_samples > 0 and X_sampled.shape[0] > max_samples:
        logger.info(f'max samples: {max_samples}')
        X_sampled = X_sampled.sample(n=max_samples, random_state=42)

    to_drop = always_drop[:]
    for c in df.columns:
        if c not in features:
            to_drop.append(c)

    numeric_columns = X_sampled.drop(columns=to_drop).select_dtypes(include='number')
    X = numeric_columns.fillna(0)  # Handle NaN values

    # Standardize the data
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    logger.info(f'starting reduction: {reduction}/{reduction_parameter}')

    # Apply the dimensionality reduction method (PCA, UMAP, or t-SNE)
    if reduction == 'none':
        if len(features) != 2:
            raise(ValueError('none reduction must have 2 features'))

        X_reduced = np.column_stack((df[features[0]], df[features[1]]))

        logger.info(f'finished reduction: {reduction}')

        return X_sampled, X_reduced
    elif reduction == 'umap':
        reduction_method = UMAP(n_components=2)
    elif reduction == 'tsne':
        reduction_method = TSNE(n_components=2, perplexity=reduction_parameter)
    elif reduction == 'pca':
        reduction_method = PCA(n_components=2)

    X_reduced = reduction_method.fit_transform(X_scaled)

    logger.info(f'finished reduction: {reduction}')

    return X_sampled, X_reduced

def compute_clustering(X_sampled, X_reduced, clustering, clustering_parameter):
    logger.info(f'starting clustering: {clustering}/{clustering_parameter}')

    if clustering == 'none':
        labels = [0] * X_sampled.shape[0]

        logger.info(f'finished clustering: {clustering}')
        return labels, ["No Label"]

    elif clustering == 'known':
        logger.info(f'finished clustering: {clustering}')

        return X_sampled['heuristic_label'].tolist(), heuristic_labels

    # Perform clustering if a clustering algorithm is selected
    if clustering == 'kmeans':
        method = KMeans(n_clusters=clustering_parameter)
    elif clustering == 'agglo':
        method = AgglomerativeClustering(n_clusters=clustering_parameter)
    elif clustering == 'hdbscan':
        min_size = max(5, X_reduced.shape[0] // 1000)
        method = HDBSCAN(cluster_selection_epsilon=clustering_parameter / 10, min_cluster_size=min_size)

    # Fit the clustering model and get the labels
    labels = method.fit_predict(X_reduced)

    min_label = min(labels)
    if min_label < 0:
        labels = labels - min_label

    possible_labels = [f'{literals[clustering]} {x}' for x in range(len(set(labels)))]
    if clustering == 'hdbscan':
        possible_labels[0] = 'HDBSCAN Noise'

    logger.info(f'finished clustering: {clustering}')

    return labels, possible_labels

@app.get("/favicon.ico")
def favicon():
    return {"message": "favicon not found"}

@app.post("/transformation")
def read_transformation(payload: GetTransformationRequest) -> GetTransformationResponse:
    try:
        payload = clean_payload(payload)

        kwargs = payload.model_dump()
        kwargs['features'] = tuple(payload.features)

        return compute(**kwargs)
    except Exception as e:
        # raise(e)
        return make_error(str(e))

@app.post("/metadata")
def read_metadata(payload: GetMetadataRequest) -> GetMetadataResponse:
    try:
        df = pd.merge(pd.Series(payload.ids).rename('index'), metadata_df, how='inner')

        return {
            'data': {
                    'length': df.shape[0],
                    'timestamp': df['timeslice'].tolist(),
                    'date': df['date'].tolist(),
                    'src_ip': df['source_ip'].tolist(),
                    'src_port': df['src_port'].tolist(),
                    'dest_ip': df['dest_ip'].tolist(),
                    'dest_port': df['dest_port'].tolist(),
                    'protocol_type': df['protocol_type'].tolist(),
                    'is_init': df['is_init'].tolist(),
                    'packet_length': df['packet_length'].tolist(),
                    'ttl': df['ttl'].tolist(),
                    'n_packets': df['n_packets'].tolist(),
                    'duration': df['duration'].tolist(),
                    'id': df['index'].tolist(),
                    'SrcASN': df['SrcASN'].tolist(),
                    'KnownScanner': df['KnownScanner'].tolist(),
                    'NetacqCountry': df['NetacqCountry'].tolist(),
                    'MaxmindCountry': df['MaxmindCountry'].tolist(),
                    # 'HueristicLabel': df['HueristicLabel'].tolist(),
            }
        }

    except Exception as e:
        # raise(e)
        return make_error(str(e))

def parse_duration(s: str) -> int:
    s = ''.join(s.split())

    if not s:
        return -1

    if s == '0':
        return 0

    duration = 0

    matches = DURATION_REGEX.findall(s)

    if len(matches) == 0:
        raise ValueError(f'parse of "{s}" failed, need at least 1 unit')

    for m in matches:
        if not m or len(m) < 3:
            continue

        if not m[0]:
            raise ValueError(f'parse of "{s}" failed, need at least 1 number')

        num = float(m[0])

        if not m[1]:
            num = int(m[0])

        unit = m[2]
        per_second = -1

        if unit == 's':
            per_second = 1
        elif unit == 'm':
            per_second = 60
        elif unit == 'h':
            per_second = 3600
        elif unit == 'd':
            per_second = 86400
        elif unit == 'w':
            per_second = 604800
        else:
            raise ValueError(f'parse of "{s}" failed, {unit} is not a valid type')

        duration += num * per_second

    return duration

@app.on_event("startup")
def startup():
    RunVar("_default_thread_limiter").set(CapacityLimiter(1))

    logging.basicConfig(
        format='%(asctime)s %(levelname)-8s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        stream=sys.stdout,
        level=logging.INFO)

    global logger
    logger = logging.getLogger(__name__)

    global timeslice_df
    timeslice_df = pd.read_parquet(args.timeslices_file)
    timeslice_df['date'] = timeslice_df['timeslice']
    timeslice_df['timeslice'] = timeslice_df['date'].map(lambda x: int(datetime.datetime.strptime(x,'%c').timestamp()))
    timeslice_df['src_ip_int'] = timeslice_df['src_ip']
    timeslice_df['src_ip'] = timeslice_df['src_ip'].map(lambda x: socket.inet_ntoa(struct.pack('!I', x)))
    timeslice_df['heuristic_label'] = timeslice_df.apply(lambda r: 0 if (r['heuristic_label'] == 1 and not r['isZMAP']) else r['heuristic_label'], axis=1)

    global first_timeslice
    first_timeslice = timeslice_df['timeslice'].min()

    global last_timeslice
    last_timeslice = timeslice_df['timeslice'].max()

    logger.info(f"Timeslice loaded successfully, timeslices: {first_timeslice}/{last_timeslice}")
    logger.info(timeslice_df.columns)

    global metadata_df
    metadata_df = pd.read_parquet(args.metadata_file)
    metadata_df['date'] = metadata_df['timeslice']
    metadata_df['timeslice'] = metadata_df['date'].map(lambda x: int(datetime.datetime.strptime(x,'%c').timestamp()))
    metadata_df['source_ip_int'] = metadata_df['source_ip']
    metadata_df['source_ip'] = metadata_df['source_ip'].map(lambda x: socket.inet_ntoa(struct.pack('!I', x)))

    metadata_df['is_init'] = metadata_df['is_init'].fillna(False)

    merged = pd.merge(metadata_df, timeslice_df, how="left", on="index")
    metadata_df['duration'] = merged['duration']
    metadata_df['n_packets'] = merged['n_packets']

    logger.info(f"Metadata loaded successfully")
    logger.info(metadata_df.columns)

def parse_arguments():
    parser = argparse.ArgumentParser(description="Process command-line arguments for the application.")
    parser.add_argument("--ip_address", type=str, default='0.0.0.0', help="The IP address to host the application.")
    parser.add_argument("--port", type=int, default=8081, help="The port number to host the application.")
    parser.add_argument("--timeslices_file", type=str, default='timeslices40k.parquet', help="The path to the timeslices file.")
    parser.add_argument("--metadata_file", type=str, default='metadata40k.parquet', help="The path to the metadata file.")
    return parser.parse_args()

if __name__ == "__main__":
    global args
    args = parse_arguments()

    uvicorn.run(app, host=args.ip_address, port=args.port, log_level='info')
