#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <pwd.h>  // for getpwuid()
#include <libgen.h>  // for basename()
#include <pwd.h>

#include <time.h>
#include <float.h>
#include <grp.h>
#include <limits.h>  // for PATH_MAX
#include <openssl/sha.h>
#include <fcntl.h>
#include <time.h>
#include <sys/types.h>
#include <libgen.h>  // para basename
#include <openssl/evp.h>  // Replace older SHA headers
#include <openssl/err.h>
// Add this to the top of the file with other includes
#include <errno.h>
#include <linux/limits.h>

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

int is_duplicate(FileInfo* file, FileInfo* files, int count, const char* exclude_path) {
    for (int i = 0; i < count; i++) {
        // Skip comparing the file with itself
        if (strcmp(exclude_path, files[i].path) == 0) continue;
        
        // Comprehensive duplicate detection criteria:
        // 1. Exact same file size
        // 2. Similar modification times (within a small window)
        // 3. Same permissions
        // 4. Same owner
        if (file->size == files[i].size &&
            abs(file->modified_time - files[i].modified_time) <= 60 && // within 1 minute
            file->permissions == files[i].permissions &&
            file->owner == files[i].owner) {
            
            // Additional check to ensure it's not the exact same file
            if (strcmp(file->path, files[i].path) != 0) {
                return 1;  // Potential duplicate or very similar file found
            }
        }
    }
    
    return 0;  // No duplicates found
}

// New function to log an alert
void log_alert(const char* alert_file, const char* alert_message) {
    // Use a more robust method to prevent duplicate logging

    FILE* log = fopen(alert_file, "a");
    if (log) {
        time_t now = time(NULL);
        char timestamp[64];
        strftime(timestamp, sizeof(timestamp), "[%a %b %d %H:%M:%S %Y] ", localtime(&now));
        
        fprintf(log, "%s%s\n", timestamp, alert_message);
        fclose(log);
    }
    
}

#define MAX_ALERT_SIZE 8192

// Función auxiliar para quitar el timestamp (asume formato [XXX])
void strip_timestamp(char* alert) {
    char* start = strchr(alert, ']');
    if (start && *(start + 1) == ' ') {
        memmove(alert, start + 2, strlen(start + 2) + 1); // +1 to copy null terminator
    }
}

// Función para verificar si un mensaje ya está registrado
int is_alert_logged(const char* alert_file, const char* alert_message) {
    FILE* log = fopen(alert_file, "r");
    if (!log) return 0;

    // Prepare a stripped-down version of the input message
    char stripped_input[MAX_ALERT_SIZE];
    const char* input_start = strstr(alert_message, "ALERTA:");
    if (!input_start) input_start = strstr(alert_message, "ALERTA CRÍTICA:");
    if (!input_start) {
        fclose(log);
        return 0;
    }
    
    // Copy the core message, removing timestamp and minor variations
    strncpy(stripped_input, input_start, MAX_ALERT_SIZE - 1);
    stripped_input[MAX_ALERT_SIZE - 1] = '\0';
    
    // More aggressive stripping of variable details
    char cleaned_input[MAX_ALERT_SIZE];
    char* cleaned_ptr = cleaned_input;
    char* stripped_ptr = stripped_input;
    
    while (*stripped_ptr) {
        if (isdigit(*stripped_ptr)) {
            // Skip precise numeric values
            while (isdigit(*stripped_ptr) || *stripped_ptr == '.' || *stripped_ptr == '-' || 
                   *stripped_ptr == ':' || *stripped_ptr == ' ') {
                stripped_ptr++;
            }
            *cleaned_ptr++ = '#';  // Replace with a placeholder
        } else {
            *cleaned_ptr++ = *stripped_ptr++;
        }
    }
    *cleaned_ptr = '\0';

    // Read and compare existing alerts
    char line[2048];
    while (fgets(line, sizeof(line), log)) {
        // Clean the existing line similarly
        char cleaned_existing[MAX_ALERT_SIZE];
        char* cleaned_existing_ptr = cleaned_existing;
        char* line_ptr = line;
        
        while (*line_ptr) {
            if (isdigit(*line_ptr)) {
                // Skip precise numeric values
                while (isdigit(*line_ptr) || *line_ptr == '.' || *line_ptr == '-' || 
                       *line_ptr == ':' || *line_ptr == ' ') {
                    line_ptr++;
                }
                *cleaned_existing_ptr++ = '#';
            } else {
                *cleaned_existing_ptr++ = *line_ptr++;
            }
        }
        *cleaned_existing_ptr = '\0';

        // Compare cleaned versions more strictly
        if (strstr(cleaned_existing, cleaned_input) || 
            strstr(cleaned_input, cleaned_existing)) {
            fclose(log);
            return 1;
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

// Modify the basename matching logic to be more robust
int is_same_file(const char* old_path, const char* new_path) {
    // Use local buffers instead of strdup to avoid potential memory issues
    char old_basename[PATH_MAX];
    char new_basename[PATH_MAX];
    
    // Safely copy basename
    strncpy(old_basename, basename(old_path), sizeof(old_basename) - 1);
    strncpy(new_basename, basename(new_path), sizeof(new_basename) - 1);
    old_basename[PATH_MAX - 1] = '\0';
    new_basename[PATH_MAX - 1] = '\0';
    
    // Remove extension
    char* old_dot = strrchr(old_basename, '.');
    char* new_dot = strrchr(new_basename, '.');
    
    if (old_dot) *old_dot = '\0';
    if (new_dot) *new_dot = '\0';
    
    return strcmp(old_basename, new_basename) == 0;
}

void check_for_anomalies(Baseline* baseline, Baseline* current) {
    int total = baseline->count;
    int suspicious = 0;



    // Ensure the alerts directory exists
    mkdir("/tmp/usb_alerts", 0755);


    // Track files that have been matched to prevent false positives
    int* matched = calloc(current->count, sizeof(int));


    for (int i = 0; i < total; i++) {
        FileInfo* old = &baseline->files[i];
        int found = 0;

        for (int j = 0; j < current->count; j++) {
            FileInfo* new = &current->files[j];

            // Improved path matching to handle extension changes
            char* old_basename = basename(old->path);
            char* new_basename = basename(new->path);

            // Check if basenames match, allowing for extension changes
            if (is_same_file(old->path, new->path)) {
                found = 1;
                matched[j] = 1;
            

                // Create alert file path based on individual file
                char alert_file[512];
                snprintf(alert_file, sizeof(alert_file), "/tmp/usb_alerts/%s_alerts.txt", basename(new->path));

                // Modify the size change detection section
                if (old->size > 0 && new->size > 0) {
                    // Calculate absolute and percentage size change
                    long size_diff = llabs(new->size - old->size);
                    double size_percentage_change = fabs((double)(new->size - old->size) / old->size) * 100.0;

                    // More flexible size change detection
                    // Trigger alert if:
                    // 1. Absolute size change is large (e.g., more than 1MB)
                    // 2. Percentage change is significant (e.g., more than 50%)
                    if (size_diff > 1024 * 1024 || size_percentage_change > 50.0) {
                        char alert_msg[1024];
                        snprintf(alert_msg, sizeof(alert_msg), 
                            "ALERTA: Cambio significativo de tamaño en %s (de %ld a %ld bytes, cambio: %.2f%%)", 
                            new->path, old->size, new->size, size_percentage_change);
                        
                        if (!is_alert_logged(alert_file, alert_msg)) {
                            log_alert(alert_file, alert_msg);
                            suspicious++;
                        }
                    }
                }

                // Extension change detection with more context
                char* old_ext = strrchr(old->path, '.');
                char* new_ext = strrchr(new->path, '.');
                
                if ((old_ext == NULL && new_ext != NULL) || 
                    (old_ext != NULL && new_ext == NULL) || 
                    (old_ext != NULL && new_ext != NULL && strcmp(old_ext, new_ext) != 0)) {
                    char alert_msg[1024];
                    snprintf(alert_msg, sizeof(alert_msg), 
                        "ALERTA: Cambio de extensión en %s (%s → %s)", 
                        new->path, 
                        old_ext ? old_ext : "sin extensión", 
                        new_ext ? new_ext : "sin extensión");
                    
                    if (!is_alert_logged(alert_file, alert_msg)) {
                        log_alert(alert_file, alert_msg);
                        suspicious++;
                    }
                }

                // Permissions change detection
                if (old->permissions != new->permissions) {
                    char alert_msg[1024];
                    snprintf(alert_msg, sizeof(alert_msg), 
                        "ALERTA: Cambio de permisos en %s (%o → %o)", 
                        new->path, old->permissions, new->permissions);
                    
                    if (!is_alert_logged(alert_file, alert_msg)) {
                        log_alert(alert_file, alert_msg);
                        suspicious++;
                    }
                }

                // Owner change detection with more robust checking
                if (old->owner != new->owner) {
                    // Get owner names for more context
                    struct passwd *old_pw = getpwuid(old->owner);
                    struct passwd *new_pw = getpwuid(new->owner);
                    
                    char old_owner_name[256] = "Unknown";
                    char new_owner_name[256] = "Unknown";
                    
                    if (old_pw) strncpy(old_owner_name, old_pw->pw_name, sizeof(old_owner_name));
                    if (new_pw) strncpy(new_owner_name, new_pw->pw_name, sizeof(new_owner_name));
                    
                    char alert_msg[1024];
                    snprintf(alert_msg, sizeof(alert_msg), 
                        "ALERTA: Cambio de propietario en %s (de UID %d/%s a UID %d/%s)", 
                        new->path, 
                        old->owner, old_owner_name, 
                        new->owner, new_owner_name);
                    
                    if (!is_alert_logged(alert_file, alert_msg)) {
                        log_alert(alert_file, alert_msg);
                        suspicious++;
                    }
                }

                // Detect time differences with high precision
                if (fabs(difftime(new->modified_time, old->modified_time)) > DBL_EPSILON) {
                    char old_time_str[64], new_time_str[64];
                    
                    // Convert timestamps to human-readable format
                    struct tm *old_tm = localtime(&old->modified_time);
                    struct tm *new_tm = localtime(&new->modified_time);
                    
                    strftime(old_time_str, sizeof(old_time_str), "%Y-%m-%d %H:%M:%S", old_tm);
                    strftime(new_time_str, sizeof(new_time_str), "%Y-%m-%d %H:%M:%S", new_tm);

                    char alert_msg[1024];
                    snprintf(alert_msg, sizeof(alert_msg), 
                            "ALERTA: Archivo modificado: %s\n"
                            "  Tiempo anterior: %ld (%s)\n"
                            "  Tiempo actual: %ld (%s)\n"
                            "  Diferencia de tiempo: %.6f segundos", 
                            new->path, 
                            old->modified_time, old_time_str,
                            new->modified_time, new_time_str,
                            fabs(difftime(new->modified_time, old->modified_time)));
                    
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

    // New files detection with improved matching
    for (int j = 0; j < current->count; j++) {
        if (!matched[j]) {
            int is_genuinely_new = 1;
            char* new_basename = basename(current->files[j].path);

            // Check if this file basename already exists in the baseline
            for (int i = 0; i < baseline->count; i++) {
                if (strcmp(basename(baseline->files[i].path), new_basename) == 0) {
                    is_genuinely_new = 0;
                    break;
                }
            }

            // In the new files detection section
            if (is_genuinely_new) {
                char alert_file[512];
                snprintf(alert_file, sizeof(alert_file), "/tmp/usb_alerts/%s_alerts.txt", new_basename);

                // Only log new file alert if it's truly a new file type
                char alert_msg[1024];
                snprintf(alert_msg, sizeof(alert_msg), "ALERTA: Nuevo archivo: %s", current->files[j].path);
                if (!is_alert_logged(alert_file, alert_msg)) 
                {
                    log_alert(alert_file, alert_msg);
                    suspicious++;
                }

                // Enhanced duplicate check with more specific logging
                char dup_msg[1024];
                snprintf(dup_msg, sizeof(dup_msg), 
                    "ALERTA: Archivo duplicado o muy similar detectado: %s\n"
                    "  Tamaño: %ld bytes\n"
                    "  Tiempo de modificación: %ld\n"
                    "  Permisos: %o\n"
                    "  Propietario: %d", 
                    current->files[j].path,
                    current->files[j].size,
                    current->files[j].modified_time,
                    current->files[j].permissions,
                    current->files[j].owner);
                
                // Check for duplicate only once
                if (is_duplicate(&current->files[j], current->files, current->count, current->files[j].path) &&
                    !is_alert_logged(alert_file, dup_msg)) {
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
        
        if (!is_alert_logged(summary_file, critical_msg)) {
            log_alert(summary_file, critical_msg);
        }
    }

    free(matched);
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
