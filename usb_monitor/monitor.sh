#!/bin/bash

USB_MOUNT_DIR="/media/$USER"
PESQUISA_PATH="./matguard"
SCANNED_LIST="/tmp/scanned_usb.list"
BASELINE_DIR="/tmp/usb_baselines"
ALERT_DIR="/tmp/usb_alerts"
HISTORY_DIR="/tmp/old_history"
HISTORY_TXT="/tmp/old_history/history.txt"
PID_DIR="/tmp/usb_pids"  # NUEVO: Almacena los PIDs de cada USB

# Cleanup function
cleanup() {
    echo "Cleaning up monitoring processes..."
    pkill -P $$
    rm -f "$SCANNED_LIST"
    rm -rf "$PID_DIR"
    echo "Monitoring stopped."
    exit 0
}

trap cleanup SIGINT SIGTERM EXIT

mkdir -p "$BASELINE_DIR" "$ALERT_DIR" "$HISTORY_DIR" "$PID_DIR"
touch "$SCANNED_LIST" "$HISTORY_TXT"

# Función para procesar un nuevo USB
process_usb() {
    local device_path="$1"
    local device_name
    device_name=$(basename "$device_path")
    local alert_file="$ALERT_DIR/${device_name}_alerts.txt"

    echo "$(date): USB detectado: $device_path" >> "$alert_file"

    # Audit setup
    sudo auditctl -D
    sudo auditctl -w $device_path -p wa -k usb_monitoring
    sudo auditctl -a exit,always -F arch=b64 \
        -S chmod -S chown -S fchmod -S fchown -S rename -S unlink \
        -k file_permission_changes
    sudo auditctl -f 1
    sudo auditctl -e 1

    "$PESQUISA_PATH" "$device_path"
    "$PESQUISA_PATH" "$device_path" >> "$alert_file" 2>&1

    echo "$device_path" >> "$SCANNED_LIST"

    # Ejecutar en segundo plano y guardar el PID
    nohup "$PESQUISA_PATH" "$device_path" monitor >> "$alert_file" 2>&1 &
    echo $! > "$PID_DIR/${device_name}.pid"
}

# Función para manejar desconexión
handle_disconnection() {
    local device_path="$1"
    local device_name
    device_name=$(basename "$device_path")

    echo "$(date): USB desconectado: $device_path" >> "$ALERT_DIR/${device_name}_alerts.txt"

    # Matar proceso de monitoreo
    if [ -f "$PID_DIR/${device_name}.pid" ]; then
        kill "$(cat "$PID_DIR/${device_name}.pid")" 2>/dev/null
        rm -f "$PID_DIR/${device_name}.pid"
    fi

    # Quitar de lista
    grep -Fxv "$device_path" "$SCANNED_LIST" > "$SCANNED_LIST.tmp" && mv "$SCANNED_LIST.tmp" "$SCANNED_LIST"
}

# Bucle principal
while true; do
    # Ver nuevos dispositivos
    for usb_dir in "$USB_MOUNT_DIR"/*; do
        if [ -d "$usb_dir" ] && ! grep -Fxq "$usb_dir" "$SCANNED_LIST"; then
            process_usb "$usb_dir"
        fi
    done

    # Verificar desconexiones
    while IFS= read -r scanned_usb; do
        if [ ! -d "$scanned_usb" ]; then
            handle_disconnection "$scanned_usb"
        fi
    done < "$SCANNED_LIST"

    sleep 5
done
