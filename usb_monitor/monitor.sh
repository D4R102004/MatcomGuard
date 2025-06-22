#!/bin/bash

USB_MOUNT_DIR="/media/$USER"
SCANNER_PATH="./usb_scanning"
PESQUISA_PATH="./matguard"
SCANNED_LIST="/tmp/scanned_usb.list"
BASELINE_DIR="/tmp/usb_baselines"
ALERT_DIR="/tmp/usb_alerts"

# Cleanup function
cleanup() {
    echo "Cleaning up monitoring processes..."
    
    # Kill all child processes of this script
    pkill -P $$
    
    # Remove the scanned list
    rm -f "$SCANNED_LIST"
    
    echo "Monitoring stopped."
    exit 0
}

# Trap signals to ensure cleanup
trap cleanup SIGINT SIGTERM EXIT

# Crear directorios si no existen
mkdir -p "$BASELINE_DIR"
mkdir -p "$ALERT_DIR"
touch "$SCANNED_LIST"

# Función para procesar un nuevo USB
process_usb() {
    local device_path="$1"
    local device_name
    device_name=$(basename "$device_path")
    local alert_file="$ALERT_DIR/${device_name}_alerts.txt"
    echo $device_path

    echo "$(date): USB detectado: $device_path" >> "$alert_file"

    # Clear existing audit logs
    sudo auditctl -D  # Delete all existing rules
    
    # More comprehensive audit rules
    sudo auditctl -w $device_path -p wa -k usb_monitoring
    sudo auditctl -a exit,always -F arch=b64 \
        -S chmod -S chown -S fchmod -S fchown -S rename -S unlink \
        -k file_permission_changes
    
    # Enable more verbose auditing
    sudo auditctl -f 1  # Fail silently on audit log errors
    sudo auditctl -e 1  # Enable auditing
    

    # Crear baseline
    "$PESQUISA_PATH" "$device_path"

    # Escaneo inicial de comparación
    "$PESQUISA_PATH" "$device_path" >> "$alert_file" 2>&1

    # Registrar dispositivo
    echo "$device_path" >> "$SCANNED_LIST"

    # Monitoreo continuo (en segundo plano)
    nohup "$PESQUISA_PATH" "$device_path" monitor >> "$alert_file" 2>&1 &
}

# Bucle principal de monitoreo
while true; do
    for usb_dir in "$USB_MOUNT_DIR"/*; do
        if [ -d "$usb_dir" ]; then
            # Verificar si no ha sido escaneado previamente
            if ! grep -Fxq "$usb_dir" "$SCANNED_LIST"; then
                process_usb "$usb_dir"
            fi
        fi
    done
    sleep 5
done