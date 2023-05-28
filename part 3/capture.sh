#!/bin/bash
echo "========================="
echo "Begining data collection "
echo "========================="
for i in {1..100}
    do
        # Create base file name
        base_file_name="data/grid_$i"
        # Generate a timestamp 
        timestamp=$(date +"%Y%m%d_%H%M%S")
        # Concatenate the timestamp with the base file name
        file_name="${base_file_name}_${timestamp}.pcap"
        # Print
        echo "Capturing $file_name ..."
        # Capture and write to file_name
        tcpdump -w $file_name tcp &
        # Process ID
        PID=$!
        # Sleep
        sleep 1
        # Send client query
        python3 client.py grid $i -T restaurant -t
        # Sleep
        sleep 3.5
        # Kill process
        kill -2 $PID
        sleep 0.3
    done
echo "========================="
echo "Data collection completed"
echo "========================="
