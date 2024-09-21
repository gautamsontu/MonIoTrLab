#!/usr/bin/env python3

import os
import logging
import csv
import time
import sys
from scapy.all import rdpcap, IP
from scapy.layers.tls.all import TLS, TLSClientHello
from collections import defaultdict
from multiprocessing import Pool

# Suppress specific warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Check for TLSExtServerName in the imported modules
try:
    from scapy.layers.tls.extensions import TLSExtServerName
except ImportError:
    TLSExtServerName = None

# Function to return a defaultdict(int)
def int_defaultdict():
    return defaultdict(int)

# Analyze TLS versions and GREASE values
def analyze_tls_versions(pcap_file_info):
    pcap_file, device_results, device_name = pcap_file_info
    try:
        packets = rdpcap(pcap_file)
        print(f"Analyzing {pcap_file}...", flush=True)

        for packet in packets:
            if TLS in packet and TLSClientHello in packet:
                client_ip = packet[IP].src
                if client_ip.startswith("192.168."):
                    process_client_hello(packet, device_results, device_name)
                    time.sleep(0.01)  # Add a short sleep to reduce CPU load
    except Exception as e:
        print(f"Error analyzing {pcap_file}: {e}", flush=True)

def process_client_hello(packet, device_results, device_name):
    try:
        client_hello = packet[TLSClientHello]
        supported_versions = sorted(get_tls_versions_from_client_hello(client_hello))

        # Convert the list of versions to a string
        versions_string = ', '.join([format_tls_version(v) for v in supported_versions])

        if device_name not in device_results:
            device_results[device_name] = int_defaultdict()

        # Increment the count for this particular set of advertised versions
        device_results[device_name][versions_string] += 1

        # Print only a summary
        print(f"Device={device_name}: Supported Versions={versions_string}", flush=True)
    except Exception as e:
        print(f"Error processing client hello in packet: {e}", flush=True)

def get_tls_versions_from_client_hello(client_hello):
    supported_versions = []
    try:
        if hasattr(client_hello, 'version'):
            supported_versions.append(client_hello.version)
        if hasattr(client_hello, 'ext') and client_hello.ext:
            for ext in client_hello.ext:
                if hasattr(ext, 'versions'):
                    supported_versions.extend(ext.versions)
    except Exception as e:
        print(f"Error extracting TLS versions: {e}", flush=True)
    return supported_versions

def format_tls_version(version):
    versions = {
        0x0300: "SSL 3.0",
        0x0301: "TLS 1.0",
        0x0302: "TLS 1.1",
        0x0303: "TLS 1.2",
        0x0304: "TLS 1.3"
    }
    return versions.get(version, f"Unknown (0x{version:04x})")

# Directory containing filtered PCAP files
base_directory = "/home/gautamsontu/MyFiles/2021/active/tls_filterd/tls"

# Output directory for analysis results
output_directory = "/home/gautamsontu/MyFiles/2021/active"

# Create the output directory if it does not exist
os.makedirs(output_directory, exist_ok=True)

# Dictionary to store unique client results per device
device_results = defaultdict(int_defaultdict)

# Output results to CSV
def write_results_to_csv(device_results):
    try:
        output_csv = os.path.join(output_directory, "tls_client_advertised_versions_2021_active.csv")
        with open(output_csv, 'w', newline='') as csvfile:
            fieldnames = ['Device', 'Advertised_Versions', 'Count']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for device_name in device_results:
                for versions, count in device_results[device_name].items():
                    row = {
                        'Device': device_name,
                        'Advertised_Versions': versions,
                        'Count': count
                    }
                    writer.writerow(row)
    except Exception as e:
        print(f"Error writing results to CSV: {e}", flush=True)

# Main analysis loop for devices
def main_analysis():
    pcap_file_info_list = []

    try:
        for device_dir in os.listdir(base_directory):
            device_path = os.path.join(base_directory, device_dir)
            device_name = os.path.basename(device_path)

            if os.path.isdir(device_path):
                print(f"Processing device directory: {device_path}", flush=True)

                for pcap_file in os.listdir(device_path):
                    pcap_path = os.path.join(device_path, pcap_file)
                    if pcap_file.endswith('.pcap'):
                        pcap_file_info_list.append((pcap_path, device_results, device_name))
        
        # Use multiprocessing to speed up the processing of PCAP files
        with Pool(processes=20) as pool:  # Increase to 20 processes
            pool.map(analyze_tls_versions, pcap_file_info_list)

        write_results_to_csv(device_results)
    except Exception as e:
        print(f"Error in main analysis: {e}", flush=True)

if __name__ == "__main__":
    main_analysis()
