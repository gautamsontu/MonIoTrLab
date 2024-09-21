#!/usr/bin/env python3

import os
import logging
import csv
from scapy.all import rdpcap, IP
from scapy.layers.tls.all import TLS, TLSClientHello
from collections import defaultdict

# Suppress specific warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Check for TLSExtServerName in the imported modules
try:
    from scapy.layers.tls.extensions import TLSExtServerName
except ImportError:
    TLSExtServerName = None

# Analyze TLS versions and GREASE values
def analyze_tls_versions(pcap_file, client_results, grease_results, device_name):
    packets = rdpcap(pcap_file)
    print(f"Analyzing {pcap_file}...")

    for packet in packets:
        if TLS in packet and TLSClientHello in packet:
            client_ip = packet[IP].src
            if client_ip.startswith("192.168."):
                process_client_hello(packet, client_results, grease_results, device_name)

def process_client_hello(packet, client_results, grease_results, device_name):
    client_hello = packet[TLSClientHello]
    supported_versions = get_tls_versions_from_client_hello(client_hello)
    grease_values = get_grease_values(client_hello)

    if device_name not in client_results:
        client_results[device_name] = set()
        grease_results[device_name] = set()

    for version in supported_versions:
        client_results[device_name].add(format_tls_version(version))
    
    for grease in grease_values:
        grease_results[device_name].add(format_tls_version(grease))

    print(f"Found client hello: Supported Versions={[format_tls_version(v) for v in supported_versions]}, GREASE={grease_values}, Device={device_name}")

def get_tls_versions_from_client_hello(client_hello):
    supported_versions = []
    if hasattr(client_hello, 'version'):
        supported_versions.append(client_hello.version)
    if hasattr(client_hello, 'ext') and client_hello.ext:
        for ext in client_hello.ext:
            if hasattr(ext, 'versions'):
                supported_versions.extend(ext.versions)
    return supported_versions

def get_grease_values(client_hello):
    grease_values = []
    if hasattr(client_hello, 'ext') and client_hello.ext:
        for ext in client_hello.ext:
            if hasattr(ext, 'versions'):
                for version in ext.versions:
                    if is_grease_value(version):
                        grease_values.append(version)
    return grease_values

def is_grease_value(value):
    # GREASE values are of the form 0x?a?a where ? can be any hex digit
    return (value & 0x0f0f) == 0x0a0a

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
base_directory = "/home/gautamsontu/MyFiles/2021/idle/tls_filterd/tls"

# Output directory for analysis results
output_directory = "/home/gautamsontu/MyFiles/2021/idle"

# Create the output directory if it does not exist
os.makedirs(output_directory, exist_ok=True)

# Dictionary to store unique client results per device
client_results = defaultdict(set)
grease_results = defaultdict(set)

# Output results to CSV
def write_results_to_csv(client_results, grease_results):
    output_csv = os.path.join(output_directory, "tls_client_supported_versions.csv")
    with open(output_csv, 'w', newline='') as csvfile:
        fieldnames = ['Device', 'Supported TLS Versions', 'GREASE Values']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for device_name in client_results:
            row = {
                'Device': device_name,
                'Supported TLS Versions': ', '.join(client_results[device_name]),
                'GREASE Values': ', '.join(grease_results[device_name])
            }
            writer.writerow(row)

# Main analysis loop for devices
def main_analysis():
    for device_dir in os.listdir(base_directory):
        device_path = os.path.join(base_directory, device_dir)
        device_name = os.path.basename(device_path)

        if os.path.isdir(device_path):
            print(f"Processing device directory: {device_path}")

            for pcap_file in os.listdir(device_path):
                pcap_path = os.path.join(device_path, pcap_file)
                if pcap_file.endswith('.pcap'):
                    analyze_tls_versions(pcap_path, client_results, grease_results, device_name)

    write_results_to_csv(client_results, grease_results)

if __name__ == "__main__":
    main_analysis()

