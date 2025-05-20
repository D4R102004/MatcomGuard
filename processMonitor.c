#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>

// Configuraciones iniciales
#define DEFAULT_INTERVAL 5 // segundos entre iteraciones
#define CPU_THRESHOLD 80.0 // % de CPU para alertas
#define MEM_THRESHOLD (100 * 1024) // KB de memoria para alertas

// Funciones a implementar
void init_process_monitor();
void monitor_processes();
void init_port_scanner();
void scan_ports();

int main(int argc, char *argv[]) {
    printf("Starting Process Monitor & Port Scanner...\n");

    // Inicializar módulos
    init_process_monitor();
    init_port_scanner();

    // Crear hilos para monitoreo y escaneo
    pthread_t monitor_thread, scanner_thread;
    if (pthread_create(&monitor_thread, NULL, (void *)monitor_processes, NULL) != 0) {
        perror("Error creating monitor thread");
        exit(EXIT_FAILURE);
    }
    if (pthread_create(&scanner_thread, NULL, (void *)scan_ports, NULL) != 0) {
        perror("Error creating scanner thread");
        exit(EXIT_FAILURE);
    }

    // Esperar hilos
    pthread_join(monitor_thread, NULL);
    pthread_join(scanner_thread, NULL);

    return 0;
}

void init_process_monitor() {
    // TODO: Inicializar estructuras de datos para almacenar información de procesos
}

void monitor_processes() {
    while (1) {
        // TODO: Leer y parsear /proc
        // TODO: Calcular uso de CPU y memoria
        // TODO: Generar alertas si es necesario

        sleep(DEFAULT_INTERVAL);
    }
}

void init_port_scanner() {
    // TODO: Inicializar estructuras de datos para el escaneo de puertos
}

void scan_ports() {
    while (1) {
        // TODO: Escanear rango de puertos TCP
        // TODO: Asociar puertos con servicios y generar informe

        sleep(DEFAULT_INTERVAL);
    }
}
