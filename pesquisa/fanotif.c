

void mostrar_proceso_modificador(const char *archivo) {
    char cmd[512];
    // Expanded search to capture multiple event types
    snprintf(cmd, sizeof(cmd),
             "/usr/sbin/ausearch -f \"%s\" -ts recent "
             "-m SYSCALL,ATTR_CHANGE,CHMOD,CHOWN 2>/dev/null",
             archivo);

    FILE *fp = popen(cmd, "r");
    if (!fp) {
        fprintf(stderr, "[DEBUG] popen failed to execute: %s\n", cmd);
        return;
    }

    // Create more comprehensive event tracking structure
    struct EventDetails {
        char comm[128];
        char exe[256];
        char tty[64];
        char uid[32];
        char event_type[64];
        char mode[32];
        char owner[64];
    } event = {0};

    char line[1024];
    int found_event = 0;

    // Reset event details
    memset(&event, 0, sizeof(event));
    strcpy(event.comm, "(no registrado)");
    strcpy(event.exe, "(no registrado)");
    strcpy(event.tty, "(no registrado)");
    strcpy(event.uid, "(no registrado)");
    strcpy(event.event_type, "(no registrado)");

    // More comprehensive parsing
    while (fgets(line, sizeof(line), fp)) {
        char *p;

        // Detect event type
        if ((p = strstr(line, "type=")) && 
            sscanf(p + 5, "%63s", event.event_type) == 1) {
            
            // Parse common fields across different event types
            if ((p = strstr(line, "comm=\"")) && 
                sscanf(p + 6, "%127[^\"]", event.comm) == 1) {
                found_event = 1;
            }
            
            if ((p = strstr(line, "exe=\"")) && 
                sscanf(p + 5, "%255[^\"]", event.exe) == 1) {
                found_event = 1;
            }
            
            if ((p = strstr(line, "tty=")) && 
                sscanf(p + 4, "%63s", event.tty) == 1) {
                found_event = 1;
            }
            
            if ((p = strstr(line, "uid=")) && 
                sscanf(p + 4, "%31s", event.uid) == 1) {
                found_event = 1;
            }

            // Specific parsing for CHMOD events
            if (strcmp(event.event_type, "CHMOD") == 0 || 
                strstr(line, "mode=")) {
                if ((p = strstr(line, "mode=")) && 
                    sscanf(p + 5, "%31s", event.mode) == 1) {
                    printf("   🔒 Cambio de permisos detectado:\n");
                    printf("      Nuevo modo: %s\n", event.mode);
                }
            }

            // Specific parsing for CHOWN events
            if (strcmp(event.event_type, "CHOWN") == 0 || 
                strstr(line, "ouid=")) {
                if ((p = strstr(line, "ouid=")) && 
                    sscanf(p + 5, "%63s", event.owner) == 1) {
                    printf("   👥 Cambio de propietario detectado:\n");
                    printf("      Nuevo propietario UID: %s\n", event.owner);
                }
            }
        }

        // If we found a complete event, print details
        if (found_event) {
            printf("   🔎 Detalles del evento para %s:\n", archivo);
            printf("      🧠 Comando: %s\n", event.comm);
            printf("      📁 Ejecutable: %s\n", event.exe);
            printf("      👤 UID: %s\n", event.uid);
            printf("      🖥 TTY: %s\n", event.tty);
            printf("      📋 Tipo de evento: %s\n", event.event_type);

            // Origin heuristics
            if (strcmp(event.tty, "(no registrado)") != 0 && 
                strcmp(event.tty, "?") != 0) {
                printf("      🧍 Probablemente un cambio manual (usuario en terminal)\n");
            } else if (strstr(event.exe, "bash") || 
                       strstr(event.exe, "sh") || 
                       strstr(event.exe, "python")) {
                printf("      🤖 Probablemente un script automático\n");
            } else {
                printf("      ❓ Origen del cambio: desconocido\n");
            }

            // Reset for next event
            found_event = 0;
            memset(&event, 0, sizeof(event));
        }
    }

    pclose(fp);

    // Fallback if no events found
    if (!found_event) {
        printf("   ⚠️ No se encontraron registros de cambio de atributos para %s\n", archivo);
    }
}