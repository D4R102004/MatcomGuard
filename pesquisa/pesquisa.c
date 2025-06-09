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

// Función para calcular hash SHA-256
void sha256sum(const char* filename, char* out_hash) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned char buffer[4096];
    SHA256_CTX sha256;
    FILE* file = fopen(filename, "rb");
    if (!file) {
        strcpy(out_hash, "ERROR");
        return;
    }

    SHA256_Init(&sha256);
    size_t bytes;
    while ((bytes = fread(buffer, 1, sizeof(buffer), file)) > 0)
        SHA256_Update(&sha256, buffer, bytes);
    SHA256_Final(hash, &sha256);
    fclose(file);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf(out_hash + (i * 2), "%02x", hash[i]);
    out_hash[64] = 0;
}

void scan_directory(const char* path, Baseline* base) {
    DIR* dir = opendir(path);
    if (!dir) return;
    printf("Escaneando: %s\n", path);

    struct dirent* entry;
    char full_path[MAX_PATH];
    struct stat st;

    while ((entry = readdir(dir)) && base->count < MAX_FILES) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);
        if (stat(full_path, &st) == -1)
            continue;

        if (S_ISDIR(st.st_mode)) {
            scan_directory(full_path, base);
        } else if (S_ISREG(st.st_mode)) {
            FileInfo* info = &base->files[base->count++];
            strncpy(info->path, full_path, MAX_PATH);
            sha256sum(full_path, info->hash);
            info->modified_time = st.st_mtime;
            info->size = st.st_size;
            info->permissions = st.st_mode & 0777;
            info->owner = st.st_uid;
        }
    }
    closedir(dir);
}

void save_baseline(const char* filename, Baseline* base) {
    FILE* f = fopen(filename, "w");
    if (!f) return;

    for (int i = 0; i < base->count; i++) {
        FileInfo* fi = &base->files[i];
        fprintf(f, "%s|%s|%ld|%ld|%o|%d\n", fi->path, fi->hash, fi->modified_time, fi->size, fi->permissions, fi->owner);
    }

    fclose(f);
}

int load_baseline(const char* filename, Baseline* base) {
    FILE* f = fopen(filename, "r");
    if (!f) return 0;

    char line[2048];
    while (fgets(line, sizeof(line), f) && base->count < MAX_FILES) {
        FileInfo* fi = &base->files[base->count++];
        sscanf(line, "%[^|]|%[^|]|%ld|%ld|%o|%d\n", fi->path, fi->hash, &fi->modified_time, &fi->size, &fi->permissions, &fi->owner);
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

void check_for_anomalies(Baseline* baseline, Baseline* current) {
    int total = baseline->count;
    int suspicious = 0;

    for (int i = 0; i < total; i++) {
        FileInfo* old = &baseline->files[i];
        int found = 0;

        for (int j = 0; j < current->count; j++) {
            FileInfo* new = &current->files[j];
            if (strcmp(old->path, new->path) == 0) {
                found = 1;

                // Crecimiento inusual
                if (old->size < 100*1024 && new->size > 500*1024*1024) {
                    printf("ALERTA: %s creció de %ld a %ld bytes\n", new->path, old->size, new->size);
                    suspicious++;
                }

                // Cambio de extensión
                char* ext_old = strrchr(old->path, '.');
                char* ext_new = strrchr(new->path, '.');
                if (ext_old && ext_new && strcmp(ext_old, ext_new) != 0) {
                    printf("ALERTA: %s cambió de extensión (%s → %s)\n", new->path, ext_old, ext_new);
                    suspicious++;
                }

                // Permisos peligrosos
                if ((new->permissions & 0777) == 0777 && old->permissions != new->permissions) {
                    printf("ALERTA: Permisos peligrosos en %s (%o → %o)\n", new->path, old->permissions, new->permissions);
                    suspicious++;
                }

                // Cambio de propietario
                if (old->owner != new->owner) {
                    printf("ALERTA: Cambio de owner en %s (UID %d → %d)\n", new->path, old->owner, new->owner);
                    suspicious++;
                }

                // Hash modificado (contenido)
                if (strcmp(old->hash, new->hash) != 0) {
                    printf("ALERTA: Contenido modificado en %s\n", new->path);
                    suspicious++;
                }

                break;
            }
        }

        if (!found) {
            printf("ALERTA: Archivo eliminado: %s\n", old->path);
            suspicious++;
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
            printf("ALERTA: Nuevo archivo: %s\n", current->files[j].path);
            suspicious++;

            if (is_duplicate(current->files[j].hash, current->files, current->count, current->files[j].path)) {
                printf("ALERTA: Archivo duplicado detectado: %s\n", current->files[j].path);
                suspicious++;
            }
        }
    }

    double perc = 100.0 * suspicious / total;
    if (perc >= CHANGE_THRESHOLD) {
        printf("ALERTA CRÍTICA: %d cambios sospechosos detectados (%.2f%%)\n", suspicious, perc);
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
