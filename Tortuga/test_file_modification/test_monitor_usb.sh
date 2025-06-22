#!/bin/bash

# Use environment variables if set, otherwise use defaults
TEST_USB_DIR="${TEST_USB_DIR:-/tmp/test_usb_simulation}"
BASELINE_DIR="${BASELINE_DIR:-/tmp/usb_baselines}"
ALERTS_DIR="${ALERTS_DIR:-/tmp/usb_alerts}"
HISTORY_DIR="${HISTORY_DIR:-/tmp/old_history}"
MATGUARD_PATH="${MATGUARD_PATH:-./matguard}"

# Clean previous test runs
cleanup() {
    echo "Cleaning up test environment..."
    rm -rf "$TEST_USB_DIR"
    rm -rf "$ALERTS_DIR"
    rm -rf "$HISTORY_DIR"
}

setup() {
    mkdir -p "$TEST_USB_DIR"
    mkdir -p "$BASELINE_DIR"
    mkdir -p "$ALERTS_DIR"
    mkdir -p "$HISTORY_DIR"

    # Create initial test files
    echo "Original content" > "$TEST_USB_DIR/file1.txt"
    echo "Another original content" > "$TEST_USB_DIR/file2.txt"
    dd if=/dev/urandom of="$TEST_USB_DIR/binary_file" bs=1M count=10
}

run_tests() {
    # Clear existing audit logs
    sudo auditctl -D  # Delete all existing rules
    
    # More comprehensive audit rules
    sudo auditctl -w /tmp/test_usb_simulation/ -p wa -k usb_monitoring
    sudo auditctl -a exit,always -F arch=b64 \
        -S chmod -S chown -S fchmod -S fchown -S rename -S unlink \
        -k file_permission_changes
    
    # Enable more verbose auditing
    sudo auditctl -f 1  # Fail silently on audit log errors
    sudo auditctl -e 1  # Enable auditing
    
    # First run to create baseline
    echo "=== Creating Baseline ==="
    "$MATGUARD_PATH" "$TEST_USB_DIR"

    # Simulate modifications with explicit logging
    echo "=== Simulating File Modifications ==="

    # 0. Modify file content to trigger significant size
    echo "=== Modifying file size ==="
    dd if=/dev/zero of="$TEST_USB_DIR/file2.txt" bs=100MB count=1 
    logger -p local0.info "FILE_MOD: Performed dd operation on file2.txt"

    # 1. Modify file content significantly
    echo "=== Changing file content ==="
    echo "Massive new content that will trigger size change" > "$TEST_USB_DIR/file1.txt"
    logger -p local0.info "FILE_MOD: Changed content of file1.txt"

    # 2. Change file permissions to dangerous mode
    echo "=== Changing file permissions ==="
    chmod 777 "$TEST_USB_DIR/file2.txt"
    logger -p local0.info "FILE_PERM: Changed permissions of file2.txt to 777"

    # 3. Create a duplicate file
    echo "=== Duplicating file ==="
    cp "$TEST_USB_DIR/file1.txt" "$TEST_USB_DIR/file3_duplicate.txt"
    logger -p local0.info "FILE_COPY: Duplicated file1.txt to file3_duplicate.txt"

    # 4. Change file owner
    echo "=== Changing file owner ==="
    sudo chown nobody "$TEST_USB_DIR/binary_file"
    logger -p local0.info "FILE_OWNER: Changed owner of binary_file to nobody"

    # 5. Change file extension
    echo "=== Renaming file ==="
    mv "$TEST_USB_DIR/binary_file" "$TEST_USB_DIR/binary_file.exe"
    logger -p local0.info "FILE_RENAME: Renamed binary_file to binary_file.exe"

    # 6. Create a new file
    echo "=== Creating new file ==="
    sudo touch "$TEST_USB_DIR/file3.txt"
    logger -p local0.info "FILE_CREATE: Created file3.txt"

    # Run monitoring mode
    echo "=== Running Monitoring Mode ==="
    "$MATGUARD_PATH" "$TEST_USB_DIR" monitor &
    MONITOR_PID=$!

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