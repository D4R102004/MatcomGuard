#!/bin/bash

# Configuration
USER_USB_DIR="/media/$USER"
TEST_USB_NAME="test_usb_simulation"
TEST_USB_DIR="${USER_USB_DIR}/${TEST_USB_NAME}"

BASELINE_DIR="/tmp/usb_baselines"
ALERTS_DIR="/tmp/usb_alerts"
HISTORY_DIR="/tmp/old_history"
MATGUARD_PATH="${MATGUARD_PATH:-./matguard}"
UI_BINARY="./main"

# Clean previous test run
cleanup() {
    echo "Cleaning up test environment..."

    # Kill background processes if running
    pkill -f "$UI_BINARY"
    pkill -f monitor.sh

    # Remove simulated USB and data
    rm -rf "$TEST_USB_DIR"
    rm -rf "$ALERTS_DIR"
    rm -rf "$HISTORY_DIR"

    echo "Environment cleaned."
}

# Setup fake USB and baseline directories
setup_usb() {
    echo "Setting up simulated USB at $TEST_USB_DIR..."
    mkdir -p "$TEST_USB_DIR"
    echo "Original content" > "$TEST_USB_DIR/file1.txt"
    echo "Another original content" > "$TEST_USB_DIR/file2.txt"
    dd if=/dev/urandom of="$TEST_USB_DIR/binary_file" bs=1M count=10
}

# Launch GTK interface and monitor.sh
start_services() {
    echo "Starting interface and monitoring system..."

    # Start the GTK interface (main binary)
    ./start_ui.sh &  # assumes this calls the binary via bash script
    UI_PID=$!



    echo "UI PID: $UI_PID"
    echo "Monitor PID: $MONITOR_PID"

    # Give some time for them to initialize
    sleep 5
}

# Simulate various USB file operations
run_usb_modifications() {
    echo "Simulating USB activity..."

    # Simulate content change
    echo "=== Changing file content ==="
    echo "Modified content" > "$TEST_USB_DIR/file1.txt"
    logger -p local0.info "FILE_MOD: Modified content in file1.txt"

    # Simulate file permission change
    echo "=== Changing permissions ==="
    chmod 777 "$TEST_USB_DIR/file2.txt"
    logger -p local0.info "FILE_PERM: Set 777 on file2.txt"

    # Create a duplicate
    echo "=== Creating duplicate ==="
    cp "$TEST_USB_DIR/file1.txt" "$TEST_USB_DIR/file3_duplicate.txt"
    logger -p local0.info "FILE_COPY: Copied file1.txt to file3_duplicate.txt"

    # Change ownership
    echo "=== Changing owner ==="
    sudo chown nobody "$TEST_USB_DIR/binary_file"
    logger -p local0.info "FILE_OWNER: Changed owner of binary_file"

    # Rename file
    echo "=== Renaming file ==="
    mv "$TEST_USB_DIR/binary_file" "$TEST_USB_DIR/binary_file.exe"
    logger -p local0.info "FILE_RENAME: Renamed binary_file"

    # Create a new file
    echo "=== Creating new file ==="
    touch "$TEST_USB_DIR/file_new.txt"
    logger -p local0.info "FILE_CREATE: Created file_new.txt"

    echo "Changes made. Waiting to view results on UI..."
    sleep 30
}

# Finalize the test
finalize_test() {
    echo "Finalizing test..."

    # Kill GTK UI and monitor
    kill $UI_PID


    sleep 2
    echo "Interface and monitor shut down."
}

# Run all steps
trap cleanup EXIT
setup_usb
start_services
run_usb_modifications
finalize_test
