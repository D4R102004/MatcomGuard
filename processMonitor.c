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

// -------------------------------------------------------------
// Configuraciones iniciales y umbrales de alerta
#define DEFAULT_INTERVAL    5               // Segundos entre revisiones de /proc
#define CLEAN_INTERVAL     180               // Cada 1 minuto
#define CPU_ALERT_SEC       1.0             // CPU acumulado en segundos
#define MEM_ALERT_KB      (50 * 1024)       // 50 MB en KB
#define IO_READ_ALERT     (10UL * 1024 * 1024)  // 10 MB leídos en bytes
#define IO_WRITE_ALERT    (10UL * 1024 * 1024)  // 10 MB escritos en bytes
#define ALERT_DIR         "Txt-Internos"
// -------------------------------------------------------------

typedef struct AlertInfo {
    pid_t pid;
    double cpu_sec;
    unsigned long mem_kb;
    unsigned long readb;
    unsigned long writeb;
    char reasons[64];
    struct AlertInfo *next;
} AlertInfo;

static pthread_mutex_t io_mutex = PTHREAD_MUTEX_INITIALIZER;
static AlertInfo *prev_alerts = NULL;

// Devuelve ticks por segundo
unsigned long get_clk_tick(void) {
    return sysconf(_SC_CLK_TCK);
}

// Construye lista enlazada de procesos que superan umbrales
AlertInfo *build_alert_list(unsigned long clk_tick) {
    DIR *dir = opendir("/proc");
    if (!dir) return NULL;
    AlertInfo *head = NULL, *tail = NULL;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (!isdigit((unsigned char)entry->d_name[0])) continue;
        pid_t pid = atoi(entry->d_name);

        // --- CPU ---
        char path[64];
        snprintf(path, sizeof(path), "/proc/%d/stat", pid);
        FILE *fs = fopen(path, "r");
        if (!fs) continue;
        for (int k = 0; k < 13; k++) fscanf(fs, "%*s");
        unsigned long utime, stime;
        fscanf(fs, "%lu %lu", &utime, &stime);
        fclose(fs);
        double cpu_sec = (double)(utime + stime) / clk_tick;

        // --- Memoria ---
        snprintf(path, sizeof(path), "/proc/%d/statm", pid);
        FILE *fm = fopen(path, "r");
        if (!fm) continue;
        unsigned long size, resident;
        fscanf(fm, "%lu %lu", &size, &resident);
        fclose(fm);
        unsigned long mem_kb = resident * (getpagesize() / 1024);

        // --- I/O ---
        snprintf(path, sizeof(path), "/proc/%d/io", pid);
        FILE *fio = fopen(path, "r");
        unsigned long rb = 0, wb = 0;
        if (fio) {
            char line[128];
            while (fgets(line, sizeof(line), fio)) {
                sscanf(line, "read_bytes: %lu", &rb);
                sscanf(line, "write_bytes: %lu", &wb);
            }
            fclose(fio);
        }

        // Determinar razones de alerta
        char reasons[64] = "";
        if (cpu_sec > CPU_ALERT_SEC)   strcat(reasons, "CPU ");
        if (mem_kb > MEM_ALERT_KB)     strcat(reasons, "MEM ");
        if (rb > IO_READ_ALERT)        strcat(reasons, "IOR ");
        if (wb > IO_WRITE_ALERT)       strcat(reasons, "IOW ");
        if (strlen(reasons) == 0) continue;

        // Crear nodo de alerta
        AlertInfo *node = malloc(sizeof(AlertInfo));
        if (!node) continue;
        node->pid     = pid;
        node->cpu_sec = cpu_sec;
        node->mem_kb  = mem_kb;
        node->readb   = rb;
        node->writeb  = wb;
        strncpy(node->reasons, reasons, sizeof(node->reasons)-1);
        node->reasons[sizeof(node->reasons)-1] = '\0';
        node->next    = NULL;

        if (!head) head = node;
        else        tail->next = node;
        tail = node;
    }
    closedir(dir);
    return head;
}

// Libera la lista enlazada
void free_alert_list(AlertInfo *list) {
    while (list) {
        AlertInfo *tmp = list;
        list = list->next;
        free(tmp);
    }
}

// Compara dos listas por PID
int alerts_equal(AlertInfo *a, AlertInfo *b) {
    AlertInfo *i;
    for (i = a; i; i = i->next) {
        AlertInfo *j; int found = 0;
        for (j = b; j; j = j->next) {
            if (i->pid == j->pid) { found = 1; break; }
        }
        if (!found) return 0;
    }
    for (i = b; i; i = i->next) {
        AlertInfo *j; int found = 0;
        for (j = a; j; j = j->next) {
            if (i->pid == j->pid) { found = 1; break; }
        }
        if (!found) return 0;
    }
    return 1;
}

// Escribe alertas en consola y en un .txt dentro de ALERT_DIR
void write_alerts(AlertInfo *alerts) {
    // Crear carpeta si no existe
    struct stat st = {0};
    if (stat(ALERT_DIR, &st) == -1) {
        if (mkdir(ALERT_DIR, 0755) != 0) {
            perror("Error creando carpeta " ALERT_DIR);
            return;
        }
    }

    // Nombre de archivo con timestamp
    time_t now = time(NULL);
    char fname[64], filepath[128];
    strftime(fname, sizeof(fname), "processes_%Y%m%d_%H%M%S.txt", localtime(&now));
    snprintf(filepath, sizeof(filepath), ALERT_DIR "/%s", fname);

    FILE *out = fopen(filepath, "w");
    if (!out) {
        perror("Error al abrir fichero de alertas");
        return;
    }

    pthread_mutex_lock(&io_mutex);
    for (AlertInfo *node = alerts; node; node = node->next) {
        char buf[256];
        snprintf(buf, sizeof(buf),
            "[Alerta] PID %d | CPU: %.2f seg | Mem: %lu KB | IO R/W: %lu/%lu bytes | Razones: %s\n",
            node->pid, node->cpu_sec, node->mem_kb, node->readb, node->writeb, node->reasons);
        printf("%s", buf);
        fprintf(out, "%s", buf);
    }
    pthread_mutex_unlock(&io_mutex);

    fclose(out);
}

// Hilo de monitoreo continuo
void *monitor_processes(void *arg) {
    unsigned long clk_tick = get_clk_tick();
    prev_alerts = build_alert_list(clk_tick);
    if (prev_alerts) write_alerts(prev_alerts);

    while (1) {
        sleep(DEFAULT_INTERVAL);
        AlertInfo *curr = build_alert_list(clk_tick);
        if (!alerts_equal(prev_alerts, curr)) {
            write_alerts(curr);
            free_alert_list(prev_alerts);
            prev_alerts = curr;
        } else {
            free_alert_list(curr);
        }
    }
    return NULL;
}

// Hilo limpiador: elimina el .txt más antiguo cada minuto
void *clean_oldest_txt(void *arg) {
    while (1) {
        sleep(CLEAN_INTERVAL);

        DIR *dir = opendir(ALERT_DIR);
        if (!dir) continue;

        struct dirent *entry;
        time_t oldest = time(NULL);
        char oldest_path[256] = "";
        struct stat st;

        // Buscar archivos .txt en ALERT_DIR
        while ((entry = readdir(dir)) != NULL) {
            size_t len = strlen(entry->d_name);
            if (len < 5) continue;
            if (strcasecmp(entry->d_name + len - 4, ".txt") != 0) continue;

            char fullpath[256];
            snprintf(fullpath, sizeof(fullpath), ALERT_DIR "/%s", entry->d_name);
            if (stat(fullpath, &st) != 0) continue;

            if (st.st_ctime < oldest) {
                oldest = st.st_ctime;
                strncpy(oldest_path, fullpath, sizeof(oldest_path)-1);
                oldest_path[sizeof(oldest_path)-1] = '\0';
            }
        }
        closedir(dir);

        // Eliminar el TXT más antiguo
        if (oldest_path[0] != '\0') {
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
    printf("Starting Process Monitor with cleaner thread...\n");
    pthread_t monitor_th, cleaner_th;

    // Iniciar hilo de monitoreo
    if (pthread_create(&monitor_th, NULL, monitor_processes, NULL) != 0) {
        perror("pthread_create (monitor)");
        return EXIT_FAILURE;
    }
    // Iniciar hilo limpiador
    if (pthread_create(&cleaner_th, NULL, clean_oldest_txt, NULL) != 0) {
        perror("pthread_create (cleaner)");
        return EXIT_FAILURE;
    }

    pthread_join(monitor_th, NULL);
    pthread_join(cleaner_th, NULL);
    return EXIT_SUCCESS;
}