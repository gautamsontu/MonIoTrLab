#!/bin/bash

# Root directories containing device folders with PCAP files
root_directories=("/net/data/iot-longitudinal/datasets/2024-summer-datasets/activity-dataset/auto_summer2024_carter"
                 "/net/data/iot-longitudinal/datasets/2024-summer-datasets/activity-dataset/gautam")

# Output directory for filtered PCAP files
output_directory="/home/gautamsontu/MyFiles/2024/active/tls_filtered"

# Hardcoded TLS filter
tshark_filter="tls"

# Create the output directory if it does not exist
mkdir -p "$output_directory"

# Loop through each root directory (auto_summer2024_carter, gautam)
for root_dir in "${root_directories[@]}"; do
    # Loop through each device directory in the root directory
    for device_dir in "$root_dir"/*/; do
        device_name=$(basename "$device_dir")
        echo "Processing device: $device_name"

        # Output directory for the current device
        output_device_dir="${output_directory}/${tshark_filter}/${device_name}"
        mkdir -p "$output_device_dir"

        # Temporary directory to store merged subfolder PCAPs
        temp_dir=$(mktemp -d)
        final_merge_command=()

        # Loop through each subdirectory within the device directory (ignoring subdirectory names)
        for sub_dir in "$device_dir"*/; do
            sub_dir_name=$(basename "$sub_dir")
            echo "Processing subdirectory: $sub_dir_name"

            # Temporary filename for the merged subfolder PCAP
            subfolder_merged_pcap="${temp_dir}/${sub_dir_name}_merged.pcap"

            # Use mergecap to merge PCAP files within this subdirectory
            mergecap_files=()
            for pcap in "$sub_dir"*.pcap; do
                # Skip files starting with "._"
                if [[ $(basename "$pcap") == ._* ]]; then
                    echo "Skipping file: $pcap"
                    continue
                fi
                echo "Adding file: $pcap"
                mergecap_files+=("$pcap")
            done

            if [ ${#mergecap_files[@]} -gt 0 ]; then
                mergecap -w "$subfolder_merged_pcap" "${mergecap_files[@]}" || { echo "Merging failed for subdirectory $sub_dir_name"; continue; }
                echo "Completed merging subdirectory: $sub_dir_name"
                final_merge_command+=("$subfolder_merged_pcap")
            else
                echo "No valid PCAP files found in subdirectory: $sub_dir_name, skipping..."
            fi
        done

        # Merge all subfolder PCAPs into a single PCAP for the device
        final_merged_filename="${output_device_dir}/${device_name}_merged.pcap"
        if [ ${#final_merge_command[@]} -gt 0 ]; then
            mergecap -w "$final_merged_filename" "${final_merge_command[@]}" || { echo "Final merging failed for device $device_name"; continue; }
            echo "Completed merging all subfolders for device: $device_name"
        else
            echo "No valid merged subfolder PCAP files found for device: $device_name, skipping..."
            continue
        fi

        # Apply TLS filter to the final merged PCAP
        final_filtered_filename="${output_device_dir}/${device_name}_${tshark_filter}.pcap"
        echo "Applying TLS filter to the merged PCAP for device: $device_name"
        
        if [ -f "$final_merged_filename" ]; then
            tshark -r "$final_merged_filename" -Y "$tshark_filter" -w "$final_filtered_filename" || { echo "TLS filtering failed for device $device_name"; continue; }
            echo "Completed TLS filtering for device: $device_name"
        else
            echo "Final merged PCAP not found for device: $device_name, skipping TLS filtering..."
        fi

        # Clean up the temporary directory
        rm -rf "$temp_dir"
    done
done

echo "Processing complete."
