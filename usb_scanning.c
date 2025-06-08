#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <time.h>
#include "message_queue.h"  // Incluir nuestra cola de mensajes
#define MAX_FINAL_MSG_SIZE 2048  // Tamaño suficiente

// Función recursiva modificada para usar MessageQueue
MessageQueue* scan_directory(const char *path) {
    MessageQueue* queue = mq_init();  // Crear cola para almacenar mensajes
    
    DIR *dir = opendir(path);
    if (!dir) {
        perror("No se pudo abrir el directorio");
        return queue;  // Retornar cola (aunque esté vacía)
    }

    struct dirent *entry;
    struct stat file_stat;
    char full_path[1024];
    char message_buffer[1024];  // Buffer para formatear mensajes

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        
        snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);
        
        if (stat(full_path, &file_stat) == -1) {
            perror("No se pudo obtener información del archivo");
            continue;
        }

        if (S_ISDIR(file_stat.st_mode)) {
            // Procesar subdirectorio recursivamente
            MessageQueue* sub_queue = scan_directory(full_path);
            
            // Combinar resultados de subdirectorios
            while (!mq_is_empty(sub_queue)) {
                char* msg = mq_dequeue(sub_queue);
                mq_enqueue(queue, msg);
                free(msg);
            }
            mq_destroy(sub_queue);
            
        } else if (S_ISREG(file_stat.st_mode)) {
            char* time_str = ctime(&file_stat.st_mtime);
            time_str[strcspn(time_str, "\n")] = 0;
            
            char message_buffer[MAX_FINAL_MSG_SIZE];
            
            snprintf(message_buffer, sizeof(message_buffer),
                     "Archivo: %s | Última modificación: %s",
                     full_path, time_str);
            
            // Forzar terminación (por si hubo truncamiento)
            message_buffer[sizeof(message_buffer)-1] = '\0';
            
            mq_enqueue(queue, message_buffer);
        }
    }
    closedir(dir);
    return queue;
}


// Función para expandir '~' al directorio HOME
void expand_tilde(const char *input_path, char *expanded_path, size_t size) {
   if (input_path[0] == '~') {
       const char *home = getenv("HOME");
       if (home) 
       {

           snprintf(expanded_path, size, "%s%s", home, input_path + 1);
       } else {
           // Sin variable HOME, solo copiamos la ruta tal cual
           strncpy(expanded_path, input_path, size);
           expanded_path[size - 1] = '\0';
       }
   } else {
       // No comienza con '~', copiar directamente
       strncpy(expanded_path, input_path, size);
       expanded_path[size - 1] = '\0';
   }
}



