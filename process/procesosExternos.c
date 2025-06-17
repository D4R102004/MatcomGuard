#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <limits.h>    // para PATH_MAX
#include <linux/limits.h>  // fallback

// -------------------------------------------------------------
// Configuraciones
#define DEFAULT_INTERVAL   5                // Segundos entre chequeos de /proc
#define CLEAN_INTERVAL    180                // Cada 1 minuto
#define ALERT_DIR         "Txt-Externos"    // Carpeta de logs USB

// Prefijos habituales de montaje USB
const char *USB_PREFIXES[] = {
    "/media/",
    "/mnt/usb",
    "/run/media/"
};
#define N_PREFIXES (sizeof(USB_PREFIXES)/sizeof(USB_PREFIXES[0]))
// -------------------------------------------------------------

static pthread_mutex_t io_mutex = PTHREAD_MUTEX_INITIALIZER;

// Comprueba si la ruta del ejecutable está en un USB
int is_usb_exec(const char *exe_path) {
    for (size_t i = 0; i < N_PREFIXES; i++) {
        if (strncmp(exe_path, USB_PREFIXES[i], strlen(USB_PREFIXES[i])) == 0)
            return 1;
    }
    return 0;
}

// Registra el proceso USB en un .txt y en pantalla
void log_usb_process(pid_t pid, const char *exe_path) {
    struct stat st = {0};
    if (stat(ALERT_DIR, &st) == -1) {
        if (mkdir(ALERT_DIR, 0755) != 0) {
            perror("Error creando carpeta " ALERT_DIR);
            return;
        }
    }

    time_t now = time(NULL);
    char timestamp[32];
    char fname[64];
    char filepath[PATH_MAX];
    strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", localtime(&now));
    snprintf(fname, sizeof(fname), "usbproc_%s_%d.txt", timestamp, pid);
    snprintf(filepath, sizeof(filepath), ALERT_DIR "/%s", fname);

    pthread_mutex_lock(&io_mutex);
    FILE *out = fopen(filepath, "w");
    if (!out) {
        perror("Error abriendo log USB");
    } else {
        char buf[512];
        snprintf(buf, sizeof(buf),
            "[Alerta USB] %s\nPID: %d\nExecutable: %s\n\n",
            timestamp, pid, exe_path);
        printf("%s", buf);
        fprintf(out, "%s", buf);
        fclose(out);
    }
    pthread_mutex_unlock(&io_mutex);
}

// Hilo que monitoriza procesos y detecta los que se lanzan desde USB
void *monitor_usb_processes(void *arg) {
    while (1) {
        DIR *proc = opendir("/proc");
        if (!proc) {
            perror("opendir /proc");
            sleep(DEFAULT_INTERVAL);
            continue;
        }
        struct dirent *entry;
        while ((entry = readdir(proc)) != NULL) {
            if (!isdigit((unsigned char)entry->d_name[0]))
                continue;
            pid_t pid = atoi(entry->d_name);

            char linkpath[PATH_MAX];
            char exe_path[PATH_MAX];
            snprintf(linkpath, sizeof(linkpath), "/proc/%d/exe", pid);
            ssize_t len = readlink(linkpath, exe_path, sizeof(exe_path) - 1);
            if (len <= 0)
                continue;
            exe_path[len] = '\0';

            if (is_usb_exec(exe_path)) {
                log_usb_process(pid, exe_path);
            }
        }
        closedir(proc);
        sleep(DEFAULT_INTERVAL);
    }
    return NULL;
}

// Hilo que elimina cada CLEAN_INTERVAL el .txt más antiguo de ALERT_DIR
void *clean_oldest_txt(void *arg) {
    while (1) {
        sleep(CLEAN_INTERVAL);

        DIR *dir = opendir(ALERT_DIR);
        if (!dir)
            continue;

        struct dirent *entry;
        time_t oldest = time(NULL);
        char oldest_path[PATH_MAX] = "";
        struct stat st;

        while ((entry = readdir(dir)) != NULL) {
            size_t len = strlen(entry->d_name);
            if (len < 5 || strcasecmp(entry->d_name + len - 4, ".txt") != 0)
                continue;

            char fullpath[PATH_MAX];
            snprintf(fullpath, sizeof(fullpath), ALERT_DIR "/%s", entry->d_name);
            if (stat(fullpath, &st) != 0)
                continue;

            if (st.st_ctime < oldest) {
                oldest = st.st_ctime;
                strncpy(oldest_path, fullpath, sizeof(oldest_path) - 1);
                oldest_path[sizeof(oldest_path) - 1] = '\0';
            }
        }
        closedir(dir);

        if (oldest_path[0]) {
            if (unlink(oldest_path) == 0) {
                printf("[Cleaner] Eliminado TXT más antiguo: %s\n", oldest_path);
            } else {
                perror("[Cleaner] Error eliminando TXT");
            }
        }
    }
    return NULL;
}

int main(void) {
    printf("Starting USB Process Monitor + Cleaner...\n");
    pthread_t monitor_th, cleaner_th;

    if (pthread_create(&monitor_th, NULL, monitor_usb_processes, NULL) != 0) {
        perror("pthread_create (monitor)");
        return EXIT_FAILURE;
    }
    if (pthread_create(&cleaner_th, NULL, clean_oldest_txt, NULL) != 0) {
        perror("pthread_create (cleaner)");
        return EXIT_FAILURE;
    }

    pthread_join(monitor_th, NULL);
    pthread_join(cleaner_th, NULL);
    return EXIT_SUCCESS;
}