#!/bin/bash

# Configuración de rutas (WSL)
USB_MOUNT_DIR="/mnt"                  # WSL monta USBs aquí (ej: /mnt/e, /mnt/f)
IGNORE_DIRS=("/mnt/c" "/mnt/e" "/mnt/wsl" )       # Unidades a ignorar (C: y E:)
SCANNER_PATH="./usb_scanning"         # Ruta del escáner (ajusta según tu proyecto)
PESQUISA_PATH="./matguard"            # Ruta de tu herramienta (ajusta)
SCANNED_LIST="/tmp/scanned_usb.list"  # Lista de USBs escaneados
BASELINE_DIR="/tmp/usb_baselines"     # Directorio de baselines
ALERT_DIR="/tmp/usb_alerts"           # Directorio de alertas

# Función de limpieza al terminar
cleanup() {
    echo "Deteniendo monitor USB..."
    pkill -P $$                      # Mata procesos hijos
    rm -f "$SCANNED_LIST"            # Elimina la lista temporal
    exit 0
}

# Captura señales de terminación
trap cleanup SIGINT SIGTERM EXIT

# Crear directorios necesarios
mkdir -p "$BASELINE_DIR" "$ALERT_DIR"
touch "$SCANNED_LIST"

# Función para procesar un USB
process_usb() {
    local device_path="$1"
    local device_name=$(basename "$device_path")
    local alert_file="$ALERT_DIR/${device_name}_alerts.txt"

    echo "$(date): Nuevo USB detectado: $device_path" >> "$alert_file"


    # # Clear existing audit logs
    # # 🧹 1. Limpiar todas las reglas existentes
    # sudo auditctl -D

    # # 🧠 2. Agregar regla de monitoreo completa para el directorio
    # sudo auditctl -a exit,always \
    # -F dir=$device_path \
    # -F perm=rwxa \
    # -F auid>=1000 -F auid!=4294967295 \
    # -k usb_monitoring

    # # 🔐 3. Agregar syscall adicionales para cambios de permisos y archivos
    # sudo auditctl -a exit,always -F arch=b64 \
    # -S chmod -S chown -S fchmod -S fchown -S rename -S unlink \
    # -F dir=/tmp/test_usb_simulation \
    # -F auid>=1000 -F auid!=4294967295 \
    # -k file_permission_changes

    # # ⚙️ 4. Activar auditoría
    # sudo auditctl -f 1  # En modo fail-silent si falla
    # sudo auditctl -e 1  # Activar auditoría

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

    
    # 1. Crear baseline
    "$PESQUISA_PATH" "$device_path" >> "$alert_file" 2>&1
    
    # 2. Escaneo inicial
    "$PESQUISA_PATH" "$device_path" scan >> "$alert_file" 2>&1
    
    # 3. Registrar dispositivo
    echo "$device_path" >> "$SCANNED_LIST"
    
    # 4. Monitoreo continuo (en segundo plano)
    nohup "$PESQUISA_PATH" "$device_path" monitor >> "$alert_file" 2>&1 &
}

# Bucle principal de monitoreo
while true; do
    for usb_dir in "$USB_MOUNT_DIR"/*; do
        # Verificar: Es directorio, no es enlace simbólico y no está en la lista de ignorados
        if [[ -d "$usb_dir" && ! -L "$usb_dir" ]]; then
            should_ignore=0D
            for ignore_dir in "${IGNORE_IRS[@]}"; do
                if [[ "$usb_dir" == "$ignore_dir" ]]; then
                    should_ignore=1
                    break
                fi
            done

            # Si no está ignorado y no ha sido escaneado antes
            if [[ "$should_ignore" -eq 0 ]] && ! grep -Fxq "$usb_dir" "$SCANNED_LIST"; then
                echo "Procesando nuevo USB: $usb_dir"
                process_usb "$usb_dir"
            fi
        fi
    done
    sleep 5  # Espera 5 segundos entre iteraciones
done