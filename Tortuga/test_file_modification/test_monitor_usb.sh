#!/bin/bash

# Use environment variables if set, otherwise use defaults
TEST_USB_DIR="${TEST_USB_DIR:-/tmp/test_usb_simulation}"
BASELINE_DIR="${BASELINE_DIR:-/tmp/usb_baselines}"
ALERTS_DIR="${ALERTS_DIR:-/tmp/usb_alerts}"
MATGUARD_PATH="${MATGUARD_PATH:-./matguard}"

# Clean previous test runs
cleanup() {
    echo "Cleaning up test environment..."
    rm -rf "$TEST_USB_DIR"
    rm -rf "$ALERTS_DIR"
}

setup() {
    mkdir -p "$TEST_USB_DIR"
    mkdir -p "$BASELINE_DIR"
    mkdir -p "$ALERTS_DIR"

    # Create initial test files
    echo "Original content" > "$TEST_USB_DIR/file1.txt"
    echo "Another original content" > "$TEST_USB_DIR/file2.txt"
    dd if=/dev/urandom of="$TEST_USB_DIR/binary_file" bs=1M count=10
}

run_tests() {
    # First run to create baseline
    echo "=== Creating Baseline ==="
    "$MATGUARD_PATH" "$TEST_USB_DIR"

    # Run monitoring mode
    echo "=== Running Monitoring Mode ==="
    "$MATGUARD_PATH" "$TEST_USB_DIR" monitor &
    MONITOR_PID=$!

    # Simulate modifications
    echo "=== Simulating File Modifications ==="

    # 0. Modify file content to trigger significant size
    dd if=/dev/zero of="$TEST_USB_DIR/file2.txt" bs=100MB count=1 # 100MB file

    # 1. Modify file content significantly
    echo "Massive new content that will trigger size change" > "$TEST_USB_DIR/file1.txt"

    # 2. Change file permissions to dangerous mode
    chmod 777 "$TEST_USB_DIR/file2.txt"

    # 3. Create a duplicate file
    cp "$TEST_USB_DIR/file1.txt" "$TEST_USB_DIR/file3_duplicate.txt"

    # 4. Change file owner
    sudo chown nobody "$TEST_USB_DIR/binary_file"

    # 5. Change file extension
    mv "$TEST_USB_DIR/binary_file" "$TEST_USB_DIR/binary_file.exe"

    # 6. Create a new file
    sudo touch "$TEST_USB_DIR/file3.txt"



    # Wait for alerts to be generated
    sleep 15

    # Kill monitoring process
    kill $MONITOR_PID

    # Display generated alerts
    echo "=== Generated Alerts ==="
    for alert in "$ALERTS_DIR"/*; do
        echo "Alert File: $alert"
        cat "$alert"
        echo "---"
    done
}

# Execute test sequence
trap cleanup EXIT
setup
run_tests