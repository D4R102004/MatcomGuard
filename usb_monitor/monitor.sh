#!/bin/bash

USB_MOUNT_DIR="/media/$USER"
SCANNER_PATH="./usb_scanning"
PESQUISA_PATH="./matguard"
SCANNED_LIST="/tmp/scanned_usb.list"
BASELINE_DIR="/tmp/usb_baselines"

# Crear directorios si no existen
mkdir -p "$BASELINE_DIR"
touch "$SCANNED_LIST"

# Función para procesar un nuevo USB
process_usb() {
    local device_path="$1"
    local device_name
    device_name=$(basename "$device_path")
    local log_file="/tmp/scan_${device_name}.log"
    local baseline_file="$BASELINE_DIR/${device_name}_baseline.txt"
    local content_file="/tmp/usb_${device_name}_content.txt"

    echo "$(date): USB detectado: $device_path" >> "$log_file"
    
    # Generar lista de contenido del USB
    find "$device_path" -type f > "$content_file"
    
    # Crear baseline inicial con pesquisa
    "$PESQUISA_PATH" "$device_path" > "$baseline_file"
    
    # Escaneo con usb_scanning 
    echo "$device_path" | "$SCANNER_PATH" "$device_path" >> "$log_file" 2>&1
    
    # Registrar dispositivo como escaneado
    echo "$device_path" >> "$SCANNED_LIST"
    
    # Monitoreo continuo (segundo plano)
    nohup bash -c "
        "$PESQUISA_PATH" "$device_path" monitor & 
    done" &
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