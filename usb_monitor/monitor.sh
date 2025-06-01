#!/bin/bash

# Directorio de monitores de dispositivos USB
USB_MOUNT_DIR="/media/$USER"

# Funcion para procesar nuevo dispositivo USB
process_usb() {
    local device_path="$1"
    echo "USB detectado en: $device_path"

    # Ejecutar programa de pesquisa solo si el directorio no está vacío
    if [ "$(ls -A "$device_path")" ]; then
        /home/sakaki2004/matcom/matguard/MatcomGuard/matguard "$device_path"
    else
        echo "Directorio USB vacío, omitiendo escaneo"
    fi
}

# Monitoreo usando udevadm
udevadm monitor --property | while read -r line; do
    if [[ "$line" =~ "DEVTYPE=partition" ]] && [[ "$line" =~ "ACTION=add" ]]; then
        # Buscar directorios
        for usb_dir in "$USB_MOUNT_DIR"/*; do 
            if [ -d "$usb_dir" ]; then
                process_usb "$usb_dir"
            fi
        done
    fi
done