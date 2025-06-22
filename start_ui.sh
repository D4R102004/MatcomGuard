#!/bin/bash

# Define output binary name
OUTPUT="main"

# Compilation command
echo "Compiling $OUTPUT..."
gcc `pkg-config --cflags gtk+-3.0` -o $OUTPUT \
    main.c \
    usb_scanning.c \
    message_queue.c \
    port_scanner.c \
    `pkg-config --libs gtk+-3.0` -lpthread

# Check if compilation succeeded
if [ $? -ne 0 ]; then
    echo "Compilation failed. Exiting."
    exit 1
fi

echo "Compilation successful."

# Cleanup function
cleanup() {
    echo "Cleaning up monitoring processes in interface..."
    
    # Kill all child processes of this script
    pkill -P $$

    pkill processMonitor
    pkill monitor.sh

    # Optional: remove generated files or temp logs here
    # rm -f /tmp/some_temp_file.txt

    echo "Monitoring stopped."
    exit 0
}

# Trap signals to run cleanup on exit
trap cleanup SIGINT SIGTERM

# Run the compiled binary in the background
./$OUTPUT &

# Save its PID if needed
MAIN_PID=$!

# Wait for the background process (so cleanup runs on Ctrl+C)
wait $MAIN_PID
