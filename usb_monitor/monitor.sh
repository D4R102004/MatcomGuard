#!/bin/bash

USB_MOUNT_DIR="/media/$USER"
SCANNER_PATH="./usb_scanning"
SCANNED_LIST="/tmp/scanned_usb.list"

# Crear archivo si no existe
touch "$SCANNED_LIST"

# Función para registrar log personalizado por dispositivo
process_usb() {
    local device_path="$1"
    local device_name
    device_name=$(basename "$device_path")
    local log_file="/tmp/scan_${device_name}.log"

    echo "$(date): USB detectado: $device_path" >> "$log_file"
    echo "Contenido del directorio:" >> "$log_file"
    ls -la "$device_path" >> "$log_file"

    if [ "$(ls -A "$device_path")" ]; then
        echo "$(date): Realizando escaneo..." >> "$log_file"
        echo "$device_path" | "$SCANNER_PATH" "$device_path" >> "$log_file" 2>&1
        echo "$device_path" >> "$SCANNED_LIST"
    else
        echo "$(date): Directorio vacío, omitiendo escaneo" >> "$log_file"
    fi
}

# Logging inicial
echo "$(date): Iniciando monitor de USB"
echo "Directorio de montaje: $USB_MOUNT_DIR"

# Bucle de monitoreo
while true; do
    for usb_dir in "$USB_MOUNT_DIR"/*; do
        if [ -d "$usb_dir" ]; then
            # Verifica si ya se escaneó
            if ! grep -Fxq "$usb_dir" "$SCANNED_LIST"; then
                process_usb "$usb_dir"
            fi
        fi
    done
    sleep 5
done
