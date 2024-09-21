import os
import csv
import json
import pyshark
import concurrent.futures
from scapy.all import rdpcap, IP
from scapy.layers.tls.all import TLS, TLSClientHello, TLSExtServerName
from collections import defaultdict
import logging

# Suppress specific warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

local_ip_block = '2001:470:8863:1aba'

script_dir = os.path.dirname(os.path.abspath(__file__))
# Load the cipher suite mapping from JSON
json_path = os.path.join(script_dir, 'cipher_suite.json')
with open(json_path, 'r') as f:
    cipher_suite_mapping = json.load(f)

# Function to extract server names using tshark
def hostname_extract(infiles, dev_name):
    ip_host = {}  # Dictionary of destination IP to hostname
    domain_list = set()
    for in_pcap in infiles:
        try:
            # Extract domain names from DNS queries
            hosts = str(os.popen("tshark -r %s -Y \"dns.flags.response && not mdns\" -T fields -e dns.qry.name -e dns.qry.type -e dns.a -e dns.aaaa"
                                 % in_pcap).read()).splitlines()
            for line in hosts:
                line = line.split("\t")
                if line[0].startswith('192.168.') or line[0].startswith(local_ip_block) \
                        or 'in-addr.arpa' in line[0] or '.local' in line[0]:
                    continue
                dns_type = line[1]
                ips = line[3].split(",") if dns_type == '28' else line[2].split(",")
                domain = line[0].lower().rstrip('.')
                domain_list.add(domain)
                for ip in ips:
                    ip_host[ip] = domain

            # Extract domain names from TLS handshake
            tls_hosts = str(os.popen("tshark -r %s -Y \"tls.handshake.extensions_server_name\" -T fields -e tls.handshake.extensions_server_name -e ip.dst"
                                     % in_pcap).read()).splitlines()
            for line in tls_hosts:
                line = line.split("\t")
                if line[0].startswith('192.168.') or 'in-addr.arpa' in line[0] or '.local' in line[0]:
                    continue
                domain = line[0].lower().rstrip('.')
                domain_list.add(domain)
                ips = line[1].split(",")
                for ip in ips:
                    ip_host[ip] = domain

        except Exception as e:
            print(f"Error extracting server names for {dev_name}: {e}")
            continue

    print(f"Extraction done: {dev_name}")
    return ip_host, domain_list

# Function to get the TLS version from ServerHello
def get_tls_version_from_server_hello(packet):
    try:
        if hasattr(packet.tls, 'handshake_version'):
            version = packet.tls.handshake_version
            if version == '0x0304':
                return 'TLS 1.3'
            elif version == '0x0303':
                return 'TLS 1.2'
            elif version == '0x0302':
                return 'TLS 1.1'
            elif version == '0x0301':
                return 'TLS 1.0'
            elif version == '0x0300':
                return 'SSL 3.0'
        return 'Unknown'
    except Exception as e:
        print(f"Error extracting TLS version: {e}")
        return 'Unknown'

# Function to extract cipher suite using PyShark
def extract_cipher_suite(pcap_file):
    cipher_suite = None
    try:
        cap = pyshark.FileCapture(pcap_file, display_filter="tls.handshake.type == 2")  # Filter for ServerHello messages
        for packet in cap:
            if hasattr(packet, 'tls'):
                if hasattr(packet.tls, 'handshake_ciphersuite'):
                    cipher_suite_hex = packet.tls.handshake_ciphersuite
                    cipher_suite = cipher_suite_mapping.get(cipher_suite_hex, cipher_suite_hex)  # Convert to human-readable form
                    break  # Stop after finding the first cipher suite
        cap.close()
    except Exception as e:
        print(f"Error extracting cipher suite from {pcap_file}: {e}")
    return cipher_suite

# Function to extract server name (SNI) from ClientHello
def extract_server_name(packet):
    try:
        if TLSClientHello in packet:
            client_hello = packet[TLSClientHello]
            if hasattr(client_hello, 'ext'):
                for ext in client_hello.ext:
                    if isinstance(ext, TLSExtServerName):
                        return ext.servernames[0].servername.decode()  # Extract and decode the server name
    except Exception as e:
        print(f"Error extracting server name: {e}")
    return "Unknown"

# Check if the cipher suite is weak or problematic
def check_cipher_suite_strength(cipher_suite):
    if cipher_suite is None:
        return False, False, False  # No cipher suite, so can't evaluate its strength

    weak_ciphers = ["EXPORT", "RC4", "DES", "3DES"]
    problematic_ciphers = ["NULL", "anon"]
    forward_secrecy_ciphers = ["ECDHE", "DHE"]

    is_weak = any(weak_cipher in cipher_suite for weak_cipher in weak_ciphers)
    is_problematic = any(problematic_cipher in cipher_suite for problematic_cipher in problematic_ciphers)
    has_forward_secrecy = any(forward_secrecy in cipher_suite for forward_secrecy in forward_secrecy_ciphers)

    return is_weak, is_problematic, has_forward_secrecy

# Process ServerHello to extract server name, TLS version, and cipher suite
def process_server_hello(pcap_file, resolved_ips, server_results, device_name, ip_host):
    cipher_suite = extract_cipher_suite(pcap_file)
    tls_version = 'Unknown'
    server_name = 'Unknown'
    try:
        # Open the PCAP file with PyShark to get the TLS version from ServerHello
        cap = pyshark.FileCapture(pcap_file, display_filter="tls.handshake.type == 2")
        for packet in cap:
            if hasattr(packet, 'tls'):
                tls_version = get_tls_version_from_server_hello(packet)
                server_name = extract_server_name(packet)
                break  # Only process the first ServerHello
        cap.close()

    except Exception as e:
        print(f"Error processing ServerHello for {device_name}: {e}")

    # Check the strength of the cipher suite
    is_weak, is_problematic, has_forward_secrecy = check_cipher_suite_strength(cipher_suite)

    # Store results
    server_results[device_name].append({
        'Device': device_name,
        'Server Name': server_name,
        'TLS Version': tls_version,
        'Cipher Suite': cipher_suite if cipher_suite else 'Unknown',
        'Weak Cipher': 'Yes' if is_weak else 'No',
        'Problematic Cipher': 'Yes' if is_problematic else 'No',
        'Forward Secrecy': 'Yes' if has_forward_secrecy else 'No'
    })

    print(f"Device: {device_name}, Server Name: {server_name}, TLS Version: {tls_version}, Cipher Suite: {cipher_suite}, "
          f"Weak Cipher: {is_weak}, Problematic Cipher: {is_problematic}, "
          f"Forward Secrecy: {has_forward_secrecy}")

# Main function to analyze PCAPs and output CSV
def analyze_device_pcaps(base_directory, out_dir):
    resolved_ips = {}
    server_results = defaultdict(list)
    dns_files = {}

    for dev_dir in os.listdir(base_directory):
        dev_name = os.path.basename(dev_dir)
        for pcap in os.listdir(os.path.join(base_directory, dev_dir)):
            pcap_path = os.path.join(base_directory, dev_dir, pcap)
            if not pcap.endswith(".pcap"):
                continue
            if dev_name in dns_files:
                dns_files[dev_name].append(pcap_path)
            else:
                dns_files[dev_name] = [pcap_path]

    # Extract server names using concurrent processing
    ip_hosts_all = {}
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_dev = {executor.submit(hostname_extract, dns_files[dev], dev): dev for dev in dns_files.keys()}
        for future in concurrent.futures.as_completed(future_to_dev):
            dev = future_to_dev[future]
            result = future.result()
            if result is not None:
                ip_host_res, _ = result
                ip_hosts_all[dev] = ip_host_res

    for device_dir in os.listdir(base_directory):
        device_path = os.path.join(base_directory, device_dir)
        device_name = os.path.basename(device_path)

        if os.path.isdir(device_path) and device_name in dns_files:
            print(f"Processing device directory: {device_path}")
            server_results[device_name] = []

            for pcap_file in os.listdir(device_path):
                pcap_path = os.path.join(device_path, pcap_file)
                if pcap_file.endswith('.pcap'):
                    process_server_hello(pcap_path, resolved_ips, server_results, device_name, ip_hosts_all.get(device_name, {}))

    # Save the extracted results to CSV
    if not os.path.exists(out_dir):
        os.makedirs(out_dir)

    csv_file = os.path.join(out_dir, "tls_analysis_results_2021.csv")
    with open(csv_file, 'w', newline='') as csvfile:
        fieldnames = [
            'Device', 'Server Name', 'TLS Version', 'Cipher Suite',
            'Weak Cipher', 'Problematic Cipher', 'Forward Secrecy'
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for device_name, results in server_results.items():
            for result in results:
                writer.writerow({
                    'Device': result['Device'],
                    'Server Name': result['Server Name'],
                    'TLS Version': result['TLS Version'],
                    'Cipher Suite': result['Cipher Suite'],
                    'Weak Cipher': result['Weak Cipher'],
                    'Problematic Cipher': result['Problematic Cipher'],
                    'Forward Secrecy': result['Forward Secrecy']
                })

# Example usage
base_directory = "/home/gautamsontu/MyFiles/2021/idle/tls_filterd/tls"
output_directory = "/home/gautamsontu/MyFiles/2021/idle"

analyze_device_pcaps(base_directory, output_directory)
