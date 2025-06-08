#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <time.h>

// Función recursiva para escanear directorios
void scan_directory(const char *path) {
    DIR *dir = opendir(path);
   if (!dir) {
       perror("No se pudo abrir el directorio");
       return;
   }
   struct dirent *entry;
   struct stat file_stat;
   char full_path[1024];
   while ((entry = readdir(dir)) != NULL) {
       if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
           continue;
       snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);
       if (stat(full_path, &file_stat) == -1) {
           perror("No se pudo obtener información del archivo");
           continue;
       }
       if (S_ISDIR(file_stat.st_mode)) {
           // Recursión para subdirectorios
           scan_directory(full_path);
       } else if (S_ISREG(file_stat.st_mode)) {
           // Archivo regular: imprime ruta y fecha de modificación
           printf("Archivo: %s | Última modificación: %s", full_path, ctime(&file_stat.st_mtime));
         
       }
   }
   closedir(dir);
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



