#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <openssl/sha.h>
#include <fcntl.h>
#include <time.h>
#include <sys/types.h>
#include <libgen.h>  // para basename
#include <openssl/evp.h>  // Replace older SHA headers
#include <openssl/err.h>
// Add this to the top of the file with other includes
#include <errno.h>

#define MAX_FILES 1000
#define MAX_PATH 1024
#define MAX_HASH_LEN 65
#define CHANGE_THRESHOLD 10.0  // Porcentaje configurable

typedef struct {
    char path[MAX_PATH];
    char hash[MAX_HASH_LEN];
    time_t modified_time;
    off_t size;
    mode_t permissions;
    uid_t owner;
} FileInfo;

typedef struct {
    FileInfo files[MAX_FILES];
    int count;
} Baseline;

// Modify sha256sum to use hex representation
void sha256sum(const char* filename, char* hash_str) {
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned int md_len;
    FILE *file;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned char buffer[4096];
    size_t bytes;

    md = EVP_sha256();
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);

    file = fopen(filename, "rb");
    if (file == NULL) {
        EVP_MD_CTX_free(mdctx);
        strcpy(hash_str, "");  // Empty string on error
        return;
    }

    while ((bytes = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        EVP_DigestUpdate(mdctx, buffer, bytes);
    }

    EVP_DigestFinal_ex(mdctx, hash, &md_len);

    // Convert to hex string
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hash_str + (i * 2), "%02x", hash[i]);
    }
    hash_str[SHA256_DIGEST_LENGTH * 2] = '\0';

    fclose(file);
    EVP_MD_CTX_free(mdctx);
}

void scan_directory(const char* path, Baseline* base) {
    DIR* dir = opendir(path);
    if (!dir) {
        // Add error logging
        fprintf(stderr, "Error opening directory: %s\n", path);
        return;
    }
    printf("Escaneando: %s\n", path);

    struct dirent* entry;
    char full_path[MAX_PATH];
    struct stat st;

    while ((entry = readdir(dir)) && base->count < MAX_FILES) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        // Skip hidden directories and system directories
        if (entry->d_name[0] == '.' || 
            strcmp(entry->d_name, "System Volume Information") == 0 ||
            strcmp(entry->d_name, ".Trash-1000") == 0)
            continue;

        snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);
        if (stat(full_path, &st) == -1)
        {
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            scan_directory(full_path, base);
        } else if (S_ISREG(st.st_mode)) {
            FileInfo* info = &base->files[base->count++];
            strncpy(info->path, full_path, MAX_PATH);
            
            // Clear hash before calculating
            memset(info->hash, 0, MAX_HASH_LEN);
            
            info->modified_time = st.st_mtime;
            info->size = st.st_size;
            info->permissions = st.st_mode & 0777;
            info->owner = st.st_uid;
        }
    }
    closedir(dir);
}

// Update save_baseline to ensure proper string handling
void save_baseline(const char* filename, Baseline* base) {
    // Ensure directory exists
    char dir_path[MAX_PATH];
    strncpy(dir_path, filename, MAX_PATH);
    char* last_slash = strrchr(dir_path, '/');
    if (last_slash) {
        *last_slash = '\0';
        mkdir(dir_path, 0755);
    }

    FILE* f = fopen(filename, "w");
    if (!f) {
        perror("Error opening baseline file");
        return;
    }

    for (int i = 0; i < base->count; i++) {
        FileInfo* fi = &base->files[i];
        // Escape potential special characters in path
        char escaped_path[MAX_PATH * 2];
        size_t j, k;
        for (j = 0, k = 0; fi->path[j] != '\0' && k < sizeof(escaped_path) - 1; j++) {
            if (fi->path[j] == '|') {
                escaped_path[k++] = '\\';
            }
            escaped_path[k++] = fi->path[j];
        }
        escaped_path[k] = '\0';

        fprintf(f, "%s|%ld|%ld|%o|%d\n", 
                escaped_path, 
                fi->modified_time, 
                fi->size, 
                fi->permissions, 
                fi->owner);
    }

    fclose(f);
}

// Update load_baseline to handle escaped paths
int load_baseline(const char* filename, Baseline* base) {
    FILE* f = fopen(filename, "r");
    if (!f) return 0;

    char line[2048];
    while (fgets(line, sizeof(line), f) && base->count < MAX_FILES) {
        FileInfo* fi = &base->files[base->count++];
        
        // Reset all fields
        memset(fi, 0, sizeof(FileInfo));

        // Parse with more robust method
        char* token = strtok(line, "|");
        if (token) {
            // Unescape path
            size_t i, j;
            for (i = 0, j = 0; token[i] != '\0'; i++, j++) {
                if (token[i] == '\\' && token[i+1] == '|') {
                    fi->path[j] = '|';
                    i++;
                } else {
                    fi->path[j] = token[i];
                }
            }
            fi->path[j] = '\0';
        }

        // Continue parsing other fields
        
        token = strtok(NULL, "|");
        if (token) fi->modified_time = atol(token);
        
        token = strtok(NULL, "|");
        if (token) fi->size = atol(token);
        
        token = strtok(NULL, "|");
        if (token) fi->permissions = strtol(token, NULL, 8);
        
        token = strtok(NULL, "|");
        if (token) fi->owner = atoi(token);
    }

    fclose(f);
    return 1;
}

int is_duplicate(const char* hash, FileInfo* files, int count, const char* exclude_path) {
    for (int i = 0; i < count; i++) {
        if (strcmp(hash, files[i].hash) == 0 && strcmp(exclude_path, files[i].path) != 0) {
            return 1;
        }
    }
    return 0;
}

// New function to log an alert
void log_alert(const char* alert_file, const char* alert_message) {
    FILE* log = fopen(alert_file, "a");
    if (!log) {
        perror("Error opening alert log file");
        return;
    }
    
    time_t now = time(NULL);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "[%a %b %d %H:%M:%S %Y] ", localtime(&now));
    
    fprintf(log, "%s%s\n", timestamp, alert_message);
    fclose(log);
}

// New function to check if an alert has been logged before
int is_alert_logged(const char* alert_file, const char* alert_message) {
    FILE* log = fopen(alert_file, "r");
    if (!log) {
        // If file doesn't exist, it means no alerts logged yet
        return 0;
    }

    char line[2048];
    while (fgets(line, sizeof(line), log)) {
        // Remove newline if present
        line[strcspn(line, "\n")] = 0;
        
        if (strstr(line, alert_message)) {
            fclose(log);
            return 1;  // Alert already logged
        }
    }
    fclose(log);
    return 0;
}

int are_files_similar(FileInfo* file1, FileInfo* file2) {
    // Compare base names first
    char* base1 = basename(file1->path);
    char* base2 = basename(file2->path);

    // If base names are different, they're not the same file
    if (strcmp(base1, base2) != 0) {
        return 0;
    }

    // Additional checks to reduce false positives
    // Compare file hash to ensure content similarity
    if (strcmp(file1->hash, file2->hash) == 0) {
        return 1;
    }

    // Optional: Add directory path similarity check
    char* dir1 = dirname(file1->path);
    char* dir2 = dirname(file2->path);

    // If directories are completely different, be more strict
    if (strcmp(dir1, dir2) != 0) {
        // Only consider as similar if file contents are identical
        return (strcmp(file1->hash, file2->hash) == 0);
    }

    return 0;
}

void check_for_anomalies(Baseline* baseline, Baseline* current) {
    int total = baseline->count;
    int suspicious = 0;



    // Ensure the alerts directory exists
    mkdir("/tmp/usb_alerts", 0755);

    for (int i = 0; i < total; i++) {
        FileInfo* old = &baseline->files[i];
        int found = 0;

        for (int j = 0; j < current->count; j++) {
            FileInfo* new = &current->files[j];
            if (strcmp(old->path, new->path) == 0) {
                found = 1;

                // Create alert file path based on individual file
                char alert_file[512];
                snprintf(alert_file, sizeof(alert_file), "/tmp/usb_alerts/%s_alerts.txt", basename(new->path));

                // Crecimiento inusual
                if (old->size < 100*1024 && new->size > 500*1024*1024) {
                    char alert_msg[1024];
                    snprintf(alert_msg, sizeof(alert_msg), "ALERTA: %s creció de %ld a %ld bytes", new->path, old->size, new->size);
                    if (!is_alert_logged(alert_file, alert_msg)) {
                        log_alert(alert_file, alert_msg);
                        suspicious++;
                    }
                }

                // Cambio de extensión
                char* base_old = basename(old->path);
                char* base_new = basename(new->path);
                char* ext_old = strrchr(old->path, '.');
                char* ext_new = strrchr(new->path, '.');

                // Check if base names match and extensions are different
                if (strcmp(base_old, base_new) == 0 && 
                    ext_old && ext_new && 
                    strcmp(ext_old, ext_new) != 0) {
                    char alert_msg[1024];
                    snprintf(alert_msg, sizeof(alert_msg), "ALERTA: %s cambió de extensión (%s → %s)", 
                            new->path, ext_old, ext_new);
                    if (!is_alert_logged(alert_file, alert_msg)) {
                        log_alert(alert_file, alert_msg);
                        suspicious++;
                    }
                }

                // Permisos peligrosos
                if ((new->permissions & 0777) == 0777 && old->permissions != new->permissions) {
                    char alert_msg[1024];
                    snprintf(alert_msg, sizeof(alert_msg), "ALERTA: Permisos peligrosos en %s (%o → %o)", new->path, old->permissions, new->permissions);
                    if (!is_alert_logged(alert_file, alert_msg)) {
                        log_alert(alert_file, alert_msg);
                        suspicious++;
                    }
                }

                // Cambio de propietario
                if (old->owner != new->owner) {
                    char alert_msg[1024];
                    snprintf(alert_msg, sizeof(alert_msg), "ALERTA: Cambio de owner en %s (UID %d → %d)", new->path, old->owner, new->owner);
                    if (!is_alert_logged(alert_file, alert_msg)) {
                        log_alert(alert_file, alert_msg);
                        suspicious++;
                    }
                }

                // Check for modification time changes
                if (old->modified_time != new->modified_time) {
                    char alert_msg[1024];
                    snprintf(alert_msg, sizeof(alert_msg), 
                             "ALERTA: Archivo modificado: %s (Tiempo anterior: %ld, Tiempo actual: %ld)", 
                             new->path, old->modified_time, new->modified_time);
                    
                    if (!is_alert_logged(alert_file, alert_msg)) {
                        log_alert(alert_file, alert_msg);
                        suspicious++;
                    }
                }


                break;
            }
        }

        // File deletion alert.
        if (!found) {
            char alert_file[512];
            snprintf(alert_file, sizeof(alert_file), "/tmp/usb_alerts/%s_alerts.txt", basename(old->path));
            
            char alert_msg[1024];
            snprintf(alert_msg, sizeof(alert_msg), "ALERTA: Archivo eliminado: %s", old->path);
            if (!is_alert_logged(alert_file, alert_msg)) {
                log_alert(alert_file, alert_msg);
                suspicious++;
            }
        }
    }

    // Nuevos archivos + duplicados
    for (int j = 0; j < current->count; j++) {
        int found = 0;
        for (int i = 0; i < baseline->count; i++) {
            if (strcmp(current->files[j].path, baseline->files[i].path) == 0) {
                found = 1;
                break;
            }
        }

        if (!found) {
            char alert_file[512];
            snprintf(alert_file, sizeof(alert_file), "/tmp/usb_alerts/%s_alerts.txt", basename(current->files[j].path));

            char alert_msg[1024];
            snprintf(alert_msg, sizeof(alert_msg), "ALERTA: Nuevo archivo: %s", current->files[j].path);
            if (!is_alert_logged(alert_file, alert_msg)) {
                log_alert(alert_file, alert_msg);
                suspicious++;
            }

            if (is_duplicate(current->files[j].hash, current->files, current->count, current->files[j].path)) {
                char dup_msg[1024];
                snprintf(dup_msg, sizeof(dup_msg), "ALERTA: Archivo duplicado detectado: %s", current->files[j].path);
                if (!is_alert_logged(alert_file, dup_msg)) {
                    log_alert(alert_file, dup_msg);
                    suspicious++;
                }
            }
        }
    }

    // Optional: Overall suspicious activity alert
    if (suspicious > 0) {
        char summary_file[512];
        snprintf(summary_file, sizeof(summary_file), "/tmp/usb_alerts/overall_suspicious_activity.txt");
        
        char critical_msg[1024];
        snprintf(critical_msg, sizeof(critical_msg), "ALERTA CRÍTICA: %d cambios sospechosos detectados", suspicious);
        log_alert(summary_file, critical_msg);
    }
}

// MAIN
int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Uso: %s <ruta_usb> [monitor]\n", argv[0]);
        return 1;
    }

    char* path = argv[1];
    char baseline_path[512];
    char path_copy[MAX_PATH];
    strncpy(path_copy, path, MAX_PATH - 1);
    path_copy[MAX_PATH - 1] = '\0';
    char* device_name = basename(path_copy);
    snprintf(baseline_path, sizeof(baseline_path), "/tmp/usb_baselines/%s_baseline.txt", device_name);

    // printf("Ruta recibida: %s\n", path);
    // printf("Ruta de baseline: %s\n", baseline_path);
    Baseline base = {0};
    Baseline current = {0};

    if (access(baseline_path, F_OK) != -1) {
        load_baseline(baseline_path, &base);
    } else {
        scan_directory(path, &base);
        save_baseline(baseline_path, &base);
        // printf("Baseline creado (%d archivos).\n", base.count);
        return 0;
    }

    if (argc == 3 && strcmp(argv[2], "monitor") == 0) {
        if (access(baseline_path, F_OK) == -1) {
            scan_directory(path, &base);
            save_baseline(baseline_path, &base);
        } else {
            load_baseline(baseline_path, &base);
        }

        while (1) {
            current.count = 0;
            scan_directory(path, &current);
            check_for_anomalies(&base, &current);
            sleep(10);
        }
    }

    return 0;
}
