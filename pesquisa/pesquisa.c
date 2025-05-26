#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <time.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <sys/types.h>
#include <openssl/evp.h>

#define MAX_FILES 1000
#define MAX_PATH_LENGTH 1024
#define CHANGE_THRESHOLD 10.0 // Alert rate percentage

// Structure for storing file data
typedef struct 
{
    char path[MAX_PATH_LENGTH]; // File Route
    unsigned char sha256_hash[SHA256_DIGEST_LENGTH]; // File's Unique Hash
    time_t last_modified; // Last modification timestamp
    long file_size; // File Size
    mode_t permissions; // File Permissions
} FileInfo;

// Structure to store baseline (initial stage) of files
typedef struct 
{
    FileInfo files[MAX_FILES];
    int file_count;
} USBBaseline;

// Function to calculate Hash
int calculate_sha256(const char* filepath, unsigned char* hash)
{
    FILE *file = fopen(filepath, "rb");

    if (!file)
        return EXIT_FAILURE; // Throw error if could not open file
    
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned int md_len;
    
    mdctx = EVP_MD_CTX_new();
    md = EVP_sha256();

    EVP_DigestInit_ex(mdctx, md, NULL);

    // SHA256_CTX sha256;
    // SHA256_Init(&sha256); // Initialize sha context
    
    unsigned char buffer[4096]; // Buffer for reading the file
    size_t bytesRead;

    // Read the file block by block
    while(
        (bytesRead = fread(buffer, 1, sizeof(buffer), file)) > 0
    )
    {
        EVP_DigestUpdate(mdctx, buffer, bytesRead); // Actualizar hash
    }

    EVP_DigestFinal(mdctx, hash, &md_len); // End hash calculations

    EVP_MD_CTX_free(mdctx);
    fclose(file);
    return EXIT_SUCCESS;
}

// Function to create the initial baseline of files in the USB device
void create_baseline(const char* path, USBBaseline* baseline)
{
    DIR *dir;
    struct dirent *entry;
    char full_path[MAX_PATH_LENGTH];
    struct stat file_stat;

    dir = opendir(path);
    if (!dir)
        return;

    while(
        ((entry = readdir(dir)) != NULL
        && baseline->file_count < MAX_FILES)
    )
    {
        // Skip special directories
        if (strcmp(entry->d_name, ".") == 0
            || strcmp(entry->d_name, "..") == 0)
            continue;
        
        // Construct full route
        snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);

        // Obtain file metadata
        if (stat(full_path, &file_stat) == -1)
            continue;
            
        // If its a directory, scan recursively:
        if (S_ISDIR(file_stat.st_mode))
        {
            create_baseline(full_path, baseline);
        }

        // If its a regular file, keep information
        else if (S_ISREG(file_stat.st_mode))
        {
            FileInfo* file_info = &baseline->files[baseline->file_count];

            // Keep Metadata
            strncpy(file_info->path, full_path, MAX_PATH_LENGTH);
            file_info->last_modified = file_stat.st_mtime;
            file_info->file_size = file_stat.st_size;
            file_info->permissions = file_stat.st_mode & 0777;

            // Calculate hash
            calculate_sha256(full_path, file_info->sha256_hash);

            baseline->file_count++;
        }
    }
    closedir(dir);
}

// Baseline comparison
int compare_state(USBBaseline* baseline, const char* path) {
    USBBaseline current_state = {0};
    create_baseline(path, &current_state);

    int modified_files = 0;

    // Compare files from original baseline
    for (int i = 0; i < baseline->file_count; i++) {
        int found = 0;
        for (int j = 0; j < current_state.file_count; j++) {
            if (strcmp(baseline->files[i].path, current_state.files[j].path) == 0) {
                found = 1;

                // Compare bit a bit
                if (memcmp(baseline->files[i].sha256_hash, 
                           current_state.files[j].sha256_hash, 
                           SHA256_DIGEST_LENGTH) != 0) {
                    printf("ALERTA: Archivo modificado: %s\n", baseline->files[i].path);
                    modified_files++;
                }

                // More metadata comparison
                if (baseline->files[i].file_size != current_state.files[j].file_size) {
                    printf("ALERTA: Cambio de tamaño en: %s\n", baseline->files[i].path);
                    modified_files++;
                }

                if (baseline->files[i].permissions != current_state.files[j].permissions) {
                    printf("ALERTA: Cambio de permisos en: %s\n", baseline->files[i].path);
                    modified_files++;
                }

                break;
            }
        }

        // Detect deleted files
        if (!found)
        {
            printf("ALERTA: Archivo eliminado: %s\n", baseline->files[i].path);
            modified_files++;
        }
    }

    // Detect new files
    for (int j = 0; j < current_state.file_count; j++)
    {
        int found = 0;
        for (int i = 0; i < baseline->file_count; i++)
        {
            if (strcmp(baseline->files[i].path, current_state.files[j].path) == 0)
            {
                found = 1;
                break;
            }
        }
        if (!found)
        {
            printf("ALERTA: Nuevo archivo detectado: %s\n", current_state.files[j].path);
            modified_files++;
        }
    }

    // Calculate rate
    double change_percentage = (double)modified_files / baseline->file_count * 100.0;

    if (change_percentage > CHANGE_THRESHOLD)
    {
        printf("ALERTA CRITICA: CAmbios significativos detectados (%.2f%%)\n", change_percentage);
        return 1;
    }

    return 0;
}

// Main monitoring function
void monitor_device(const char* mount_path)
{
    USBBaseline initial_baseline = {0};

    // Create Initial Baseline
    create_baseline(mount_path, &initial_baseline);
    printf("Baseline inicial creado con %d archivos\n", initial_baseline.file_count);

    // Continuoues monitoring
    while (1)
    {
        sleep(30);
        printf("Monitoring...\n");
        compare_state(&initial_baseline, mount_path);
    }
}

int main()
{
    char mount_path[256];
    printf("Input route: ");
    scanf("%255s", mount_path);

    monitor_device(mount_path);
    return 0;
}