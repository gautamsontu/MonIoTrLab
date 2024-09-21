import os
import csv
from scapy.all import *
from scapy.layers.tls.all import *
from collections import defaultdict
import logging

# Suppress specific warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Updated list of devices to process
device_list = [
    "amazon-plug", "echodot", "echospot", "homepod", "lefun-cam-wired", "philips-bulb", "sousvide", "tuya-camera", "yi-camera",
    "aqara-hub", "echodot3a", "fridge", "homepod-mini1", "magichome-strip", "ring-camera", "switchbot-hub", "t-wemo-plug",
    "brewer", "echodot4b", "google-home-mini", "icsee-doorbell", "meross-dooropener", "ring-chime1", "thermopro-sensor", "ubell-doorbell",
    "bulb1", "echoflex1", "google-nest-mini1", "ikea-hub", "microseven-camera", "ring-doorbell", "t-philips-hub", "wansview-cam-wired",
    "dlink-camera", "echoplus", "gosund-bulb1", "ikettle", "microwave", "smartlife-bulb", "tplink-bulb", "wink-hub2",
    "dlink-mov", "echoshow5", "govee-led1", "keyco-air", "nest-tstat", "smartthings-hub", "tplink-plug", "wyze-cam"
]

# Function to return a defaultdict(int)
def int_defaultdict():
    return defaultdict(int)

# Function to get the TLS version from ServerHello and check for downgrade protection
def get_tls_version_from_server_hello(server_hello):
    try:
        # Check for TLS 1.3 supported_versions extension
        if hasattr(server_hello, 'ext') and server_hello.ext:
            for ext in server_hello.ext:
                if hasattr(ext, 'version'):
                    # TLS 1.3
                    if ext.version == 0x0304:
                        print("TLS 1.3 Found!")
                        # Check for downgrade protection
                        if hasattr(server_hello, 'downgrade'):
                            print(f"Downgrade protection: {server_hello.downgrade}")
                        return 0x0304  # Return TLS 1.3 hex value

        # Fallback to legacy version for TLS 1.2 and earlier
        return server_hello.version  # Return legacy version for TLS 1.2 or older
    except Exception as e:
        print(f"Error extracting TLS version from ServerHello: {e}", flush=True)
        return None

# Function to format the TLS version into a readable string
def format_tls_version(version):
    versions = {
        0x0300: "SSL 3.0",
        0x0301: "TLS 1.0",
        0x0302: "TLS 1.1",
        0x0303: "TLS 1.2",
        0x0304: "TLS 1.3"
    }
    return versions.get(version, f"Unknown (0x{version:04x})")

# Process ServerHello to extract established version
def process_server_hello(packet, device_results, device_name):
    try:
        server_hello = packet[TLSServerHello]
        established_version = get_tls_version_from_server_hello(server_hello)

        if established_version is None:
            return

        # Convert the version to a string
        version_string = format_tls_version(established_version)

        if device_name not in device_results:
            device_results[device_name] = int_defaultdict()

        # Increment the count for this particular established version
        device_results[device_name][version_string] += 1

        # Print when a ServerHello is processed
        print(f"Processed ServerHello for device: {device_name}, Established Version: {version_string}", flush=True)

    except Exception as e:
        print(f"Error processing ServerHello in packet: {e}", flush=True)

# Main function to analyze PCAPs and output CSV
def analyze_device_pcaps(base_directory, out_dir):
    device_results = defaultdict(int_defaultdict)

    for device_dir in os.listdir(base_directory):
        device_path = os.path.join(base_directory, device_dir)
        device_name = os.path.basename(device_path)

        if device_name not in device_list:
            print(f"Skipping device directory: {device_name} (not in the device list)", flush=True)
            continue

        if os.path.isdir(device_path):
            print(f"Processing device directory: {device_path}", flush=True)

            for pcap_file in os.listdir(device_path):
                pcap_path = os.path.join(device_path, pcap_file)
                if pcap_file.endswith('.pcap'):
                    print(f"Analyzing PCAP file: {pcap_path}", flush=True)
                    try:
                        packets = rdpcap(pcap_path)

                        for packet in packets:
                            if TLS in packet and TLSServerHello in packet:
                                process_server_hello(packet, device_results, device_name)
                    except Exception as e:
                        print(f"Error reading PCAP file {pcap_path}: {e}", flush=True)

    # Save the extracted results to CSV
    if not os.path.exists(out_dir):
        os.makedirs(out_dir)

    csv_file = os.path.join(out_dir, "tls_established_versions_idle_2021_new_new.csv")
    with open(csv_file, 'w', newline='') as csvfile:
        fieldnames = ['Device', 'Established Version', 'Count']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for device_name, versions in device_results.items():
            for version, count in versions.items():
                writer.writerow({
                    'Device': device_name,
                    'Established Version': version,
                    'Count': count
                })

    print(f"Results saved to: {csv_file}", flush=True)

# Example usage
base_directory = "/home/gautamsontu/MyFiles/2021/idle/tls_filterd/tls"
output_directory = "/home/gautamsontu/MyFiles/2021/idle"

analyze_device_pcaps(base_directory, output_directory)
