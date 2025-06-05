#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>

// -------------------------------------------------------------
// Configuraciones iniciales y umbrales
#define DEFAULT_INTERVAL 5         // Segundos entre cada revisión de /proc
#define CPU_THRESHOLD   80.0       // (No usado al mostrar todos los procesos)
#define MEM_THRESHOLD  (100 * 1024) // (No usado al mostrar todos los procesos)
// -------------------------------------------------------------

typedef struct ProcInfo {
    pid_t pid;               // Identificador de proceso
    struct ProcInfo *next;   // Puntero al siguiente nodo en la lista
} ProcInfo;

// Lista global de PIDs ya vistos
static ProcInfo *proc_list = NULL;

// Mutex para sincronizar salidas a consola
static pthread_mutex_t io_mutex = PTHREAD_MUTEX_INITIALIZER;

// Prototipos de funciones
void init_process_monitor(void);
void *monitor_processes(void);
unsigned long get_clk_tick(void);

// -------------------------------------------------------------

/*
 * main:
 *   - Punto de entrada del programa.
 *   - Inicializa el monitor de procesos.
 *   - Lanza un hilo que ejecuta monitor_processes() en bucle.
 */
int main(int argc, char *argv[]) {
    printf("Starting Process Monitor (mostrará procesos nuevos con CPU y Mem)...\n");

    init_process_monitor();

    pthread_t monitor_thread;
    if (pthread_create(&monitor_thread, NULL, monitor_processes, NULL) != 0) {
        perror("Error creando hilo de monitoreo");
        exit(EXIT_FAILURE);
    }

    // El hilo corre indefinidamente; aquí solo esperamos
    pthread_join(monitor_thread, NULL);
    return 0;
}

/*
 * init_process_monitor:
 *   - Inicializa la lista enlazada de procesos vistos.
 */
void init_process_monitor(void) {
    proc_list = NULL;
}

/*
 * get_clk_tick:
 *   - Retorna la cantidad de ticks de reloj por segundo.
 *   - sysconf(_SC_CLK_TCK) es portátil en Linux/Unix.
 */
unsigned long get_clk_tick(void) {
    return sysconf(_SC_CLK_TCK);
}

/*
 * monitor_processes:
 *   - Recorre /proc cada DEFAULT_INTERVAL segundos.
 *   - Por cada entrada numérica (PID):
 *       * Verifica si ya está en proc_list.
 *       * Si no está, lo agrega, lee /proc/[pid]/stat y statm para obtener
 *         CPU acumulado (utime+stime) y memoria residente, y muestra:
 *           "[Alerta] Nuevo Proceso detectado -> PID X | CPU: Y seg | Mem: Z KB"
 */
void *monitor_processes(void) {
    unsigned long clk_tick = get_clk_tick();
    
    // Primero, construir la lista inicial de PIDs y generar el archivo inicial
    ProcInfo *prev_list = NULL;
    DIR *dir = opendir("/proc");
    if (dir) {
        struct dirent *entry;
        ProcInfo *tail = NULL;
        while ((entry = readdir(dir)) != NULL) {
            if (!isdigit((unsigned char)entry->d_name[0])) continue;
            pid_t pid = (pid_t)atoi(entry->d_name);
            ProcInfo *node = malloc(sizeof(ProcInfo));
            if (!node) continue;
            node->pid = pid;
            node->next = NULL;
            if (!prev_list) prev_list = node;
            else tail->next = node;
            tail = node;
        }
        closedir(dir);
    }
    
    // Generar archivo inicial con todos los procesos actuales
    if (prev_list) {
        time_t now0 = time(NULL);
        char filename0[64];
        struct tm *tm_info0 = localtime(&now0);
        strftime(filename0, sizeof(filename0), "processes_%Y%m%d_%H%M%S.txt", tm_info0);
        FILE *outfile0 = fopen(filename0, "w");
        if (outfile0) {
            for (ProcInfo *i = prev_list; i; i = i->next) {
                pid_t pid = i->pid;
                char path_stat[64], path_mem[64];
                snprintf(path_stat, sizeof(path_stat), "/proc/%d/stat", pid);
                snprintf(path_mem, sizeof(path_mem), "/proc/%d/statm", pid);

                FILE *fstat = fopen(path_stat, "r");
                FILE *fmem  = fopen(path_mem, "r");
                if (fstat && fmem) {
                    unsigned long utime, stime;
                    for (int k = 0; k < 13; k++) fscanf(fstat, "%*s");
                    fscanf(fstat, "%lu %lu", &utime, &stime);
                    fclose(fstat);

                    unsigned long size, resident;
                    fscanf(fmem, "%lu %lu", &size, &resident);
                    fclose(fmem);

                    double cpu_seconds = (double)(utime + stime) / clk_tick;
                    unsigned long mem_kb = resident * (getpagesize() / 1024);

                    pthread_mutex_lock(&io_mutex);
                    printf("PID %d | CPU: %.2f seg | Mem: %lu KB\n", pid, cpu_seconds, mem_kb);
                    pthread_mutex_unlock(&io_mutex);

                    fprintf(outfile0, "PID %d | CPU: %.2f seg | Mem: %lu KB\n", pid, cpu_seconds, mem_kb);
                } else {
                    if (fstat) fclose(fstat);
                    if (fmem) fclose(fmem);
                }
            }
            fclose(outfile0);
        }
    }

    // Bucle para posteriores cambios
    while (1) {
        sleep(DEFAULT_INTERVAL);
        dir = opendir("/proc");
        if (!dir) continue;

        // Construir lista actual de PIDs
        ProcInfo *curr_list = NULL;
        ProcInfo *tail = NULL;
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (!isdigit((unsigned char)entry->d_name[0])) continue;
            pid_t pid = (pid_t)atoi(entry->d_name);
            ProcInfo *node = malloc(sizeof(ProcInfo));
            if (!node) continue;
            node->pid = pid;
            node->next = NULL;
            if (!curr_list) curr_list = node;
            else tail->next = node;
            tail = node;
        }
        closedir(dir);

        // Comparar prev_list y curr_list para detectar cambios en PIDs
        int changed = 0;
        for (ProcInfo *i = curr_list; i; i = i->next) {
            int found = 0;
            for (ProcInfo *j = prev_list; j; j = j->next) {
                if (i->pid == j->pid) { found = 1; break; }
            }
            if (!found) { changed = 1; break; }
        }
        if (!changed) {
            for (ProcInfo *i = prev_list; i; i = i->next) {
                int found = 0;
                for (ProcInfo *j = curr_list; j; j = j->next) {
                    if (i->pid == j->pid) { found = 1; break; }
                }
                if (!found) { changed = 1; break; }
            }
        }

        if (changed) {
            // Generar nuevo archivo con timestamp
            time_t now = time(NULL);
            char filename[64];
            struct tm *tm_info = localtime(&now);
            strftime(filename, sizeof(filename), "processes_%Y%m%d_%H%M%S.txt", tm_info);

            FILE *outfile = fopen(filename, "w");
            if (outfile) {
                for (ProcInfo *i = curr_list; i; i = i->next) {
                    pid_t pid = i->pid;
                    char path_stat[64], path_mem[64];
                    snprintf(path_stat, sizeof(path_stat), "/proc/%d/stat", pid);
                    snprintf(path_mem, sizeof(path_mem), "/proc/%d/statm", pid);

                    FILE *fstat = fopen(path_stat, "r");
                    FILE *fmem  = fopen(path_mem, "r");
                    if (fstat && fmem) {
                        unsigned long utime, stime;
                        for (int k = 0; k < 13; k++) fscanf(fstat, "%*s");
                        fscanf(fstat, "%lu %lu", &utime, &stime);
                        fclose(fstat);

                        unsigned long size, resident;
                        fscanf(fmem, "%lu %lu", &size, &resident);
                        fclose(fmem);

                        double cpu_seconds = (double)(utime + stime) / clk_tick;
                        unsigned long mem_kb = resident * (getpagesize() / 1024);

                        pthread_mutex_lock(&io_mutex);
                        printf("PID %d | CPU: %.2f seg | Mem: %lu KB\n", pid, cpu_seconds, mem_kb);
                        pthread_mutex_unlock(&io_mutex);

                        fprintf(outfile, "PID %d | CPU: %.2f seg | Mem: %lu KB\n", pid, cpu_seconds, mem_kb);
                    } else {
                        if (fstat) fclose(fstat);
                        if (fmem) fclose(fmem);
                    }
                }
                fclose(outfile);
            }

            // Liberar prev_list
            while (prev_list) {
                ProcInfo *tmp = prev_list;
                prev_list = prev_list->next;
                free(tmp);
            }
            // Asignar curr_list a prev_list y reiniciar curr_list
            prev_list = curr_list;
            curr_list = NULL;
        } else {
            // Si no hay cambios, liberar curr_list
            while (curr_list) {
                ProcInfo *tmp = curr_list;
                curr_list = curr_list->next;
                free(tmp);
            }
        }
    }
    return NULL;
}