#!/bin/bash

# Root directory containing device folders with PCAP files
pcap_directory="/net/data/iot-longitudinal/datasets/2019-datasets/iot-idle/us"

# Output directory for filtered PCAP files
output_directory="/home/gautamsontu/MyFiles/2019/idle/us/tls_filterd"

# Hardcoded TLS filter
tshark_filter="tls"

# Create the output directory if it does not exist
mkdir -p "$output_directory"

# Loop through each device directory in the root pcap directory
for device_dir in "$pcap_directory"/*/; do
    device_name=$(basename "$device_dir")
    echo "Processing device: $device_name"
    
    # Path to the 'unctrl' subdirectory within each device directory
    unctrl_path="${device_dir}unctrl/"
    
    if [ -d "$unctrl_path" ]; then
        # Output directory for the current device
        output_device_dir="${output_directory}/${tshark_filter}/${device_name}"
        mkdir -p "$output_device_dir"

        # Output filename for the merged and filtered PCAP
        output_filename="${output_device_dir}/${device_name}_${tshark_filter}.pcap"

        # Initialize an empty string for the merge command
        merge_command=""

        # Loop through each PCAP file in the 'unctrl' directory
        for pcap in "$unctrl_path"*.pcap; do
            echo "Adding file: $pcap to the merge list"
            merge_command="${merge_command} -r ${pcap}"
        done

        # Merge and filter the PCAP files, then write to the output file
        if [ -n "$merge_command" ]; then
            tshark $merge_command -w - | tshark -r - -Y "$tshark_filter" -w "$output_filename" || { echo "tshark processing failed for device $device_name"; continue; }
        fi
    else
        echo "No 'unctrl' directory found for device: $device_name, skipping..."
    fi
done

echo "Processing complete."
