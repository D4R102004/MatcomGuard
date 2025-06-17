#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/select.h>
#include <pthread.h>
#include "message_queue.h"  // Incluir el header de la cola de mensajes

#define MAX_THREADS 200
#define TIMEOUT_SEC 1
#define TIMEOUT_USEC 0
#define MAX_MSG_SIZE 1024  // Tamaño máximo para los mensajes

int total_puertosabiertos = 0;

typedef struct {
    int puerto;
    const char *servicio;
} Servicio;

Servicio servicios_comunes[] = {
    {20, "FTP-DATA"}, {21, "FTP"}, {22, "SSH"}, {23, "TELNET"},
    {25, "SMTP"}, {53, "DNS"}, {80, "HTTP"}, {110, "POP3"},
    {143, "IMAP"}, {443, "HTTPS"}, {445, "SMB"}, {3306, "MySQL"},
    {3389, "RDP"}, {0, NULL}
};

Servicio puertos_riesgo[] = {
    {4444, "Metasploit/Reverse Shell"},
    {31337, "Backdoor Elite"},
    {6667, "IRC (Usado por bots)"},
    {8080, "Proxy HTTP"},
    {9999, "Servicios no estándar"},
    {0, NULL}
};

typedef struct {
    const char *ip;
    int inicio;
    int fin;
    int alertas_count;
    MessageQueue* queue;  // Puntero a la cola de mensajes
} ScanParams;

const char* buscar_servicio(Servicio *lista, int puerto) {
    for(int i = 0; lista[i].servicio != NULL; i++) {
        if(lista[i].puerto == puerto) {
            return lista[i].servicio;
        }
    }
    return "DESCONOCIDO";
}

int escanear_puerto(const char *ip, int puerto) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0) return -1;

    fcntl(sock, F_SETFL, O_NONBLOCK);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(puerto);
    inet_pton(AF_INET, ip, &addr.sin_addr);

    connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    
    fd_set set;
    FD_ZERO(&set);
    FD_SET(sock, &set);
    
    struct timeval timeout = {TIMEOUT_SEC, TIMEOUT_USEC};
    
    int rv = select(sock + 1, NULL, &set, NULL, &timeout);
    int error = 0;
    socklen_t len = sizeof(error);
    
    if(rv > 0) {
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len);
    } else {
        error = 1;
    }
    
    close(sock);
    return (error == 0) ? 1 : 0;
}

int es_sospechoso(int puerto) {
    for(int i = 0; puertos_riesgo[i].servicio != NULL; i++) {
        if(puertos_riesgo[i].puerto == puerto) return 1;
    }
    
    const char *servicio = buscar_servicio(servicios_comunes, puerto);
    return (puerto > 1024 && strcmp(servicio, "DESCONOCIDO") == 0);
}

void* escanear_rango(void* arg) {
    ScanParams* params = (ScanParams*)arg;
    char buffer[MAX_MSG_SIZE];
    
    for(int puerto = params->inicio; puerto <= params->fin; puerto++) {
        int resultado = escanear_puerto(params->ip, puerto);
        
        if(resultado == 1) {
            const char *servicio = buscar_servicio(servicios_comunes, puerto);
            
            // Bloquear para evitar condiciones de carrera
            static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
            pthread_mutex_lock(&mutex);
            
            total_puertosabiertos++;
            snprintf(buffer, MAX_MSG_SIZE, "[+] Puerto %d abierto - Servicio: %s", 
                     puerto, servicio);
            mq_enqueue(params->queue, buffer);
            
            if(es_sospechoso(puerto)) {
                const char *razon = buscar_servicio(puertos_riesgo, puerto);
                if(strcmp(razon, "DESCONOCIDO") == 0) 
                    razon = "Puerto alto sin servicio identificado";
                
                snprintf(buffer, MAX_MSG_SIZE, "    ⚠️  ALERTA: %s", razon);
                mq_enqueue(params->queue, buffer);
                params->alertas_count++;
            }
            pthread_mutex_unlock(&mutex);
        }
    }
    return NULL;
}

// Función principal modificada para usar la cola de mensajes
void scan_ports(MessageQueue* queue, const char *ip, const char *rango) {
    total_puertosabiertos = 0;  // Reiniciar contador
    char buffer[MAX_MSG_SIZE];
    
    int inicio, fin;
    if(sscanf(rango, "%d-%d", &inicio, &fin) != 2) {
        snprintf(buffer, MAX_MSG_SIZE, "Formato de rango inválido. Use: inicio-fin");
        mq_enqueue(queue, buffer);
        return;
    }
    
    snprintf(buffer, MAX_MSG_SIZE, 
             "[*] Escaneando %s (puertos %d-%d) con %d hilos...", 
             ip, inicio, fin, MAX_THREADS);
    mq_enqueue(queue, buffer);
    
    int total_puertos = fin - inicio + 1;
    int puertos_por_hilo = total_puertos / MAX_THREADS;
    if(puertos_por_hilo < 1) puertos_por_hilo = 1;
    
    pthread_t threads[MAX_THREADS];
    ScanParams params[MAX_THREADS];
    int alertas_total = 0;
    int hilos_activos = 0;
    
    int current_start = inicio;
    for(int i = 0; i < MAX_THREADS && current_start <= fin; i++) {
        params[i].ip = ip;
        params[i].inicio = current_start;
        params[i].fin = current_start + puertos_por_hilo - 1;
        params[i].alertas_count = 0;
        params[i].queue = queue;  // Asignar la cola de mensajes
        
        if(params[i].fin > fin) params[i].fin = fin;
        
        pthread_create(&threads[i], NULL, escanear_rango, &params[i]);
        hilos_activos++;
        
        current_start += puertos_por_hilo;
    }
    
    for(int i = 0; i < hilos_activos; i++) {
        pthread_join(threads[i], NULL);
        alertas_total += params[i].alertas_count;
    }
    
    // Añadir resultados finales a la cola
    mq_enqueue(queue, "\n--- ESCANEO COMPLETADO ---");
    snprintf(buffer, MAX_MSG_SIZE, "Puertos abiertos: %d", total_puertosabiertos);
    mq_enqueue(queue, buffer);
    snprintf(buffer, MAX_MSG_SIZE, "Alertas de seguridad: %d", alertas_total);
    mq_enqueue(queue, buffer);
}