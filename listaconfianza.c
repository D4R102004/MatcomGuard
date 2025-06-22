#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * list_trusted.c
 *
 * Genera un CSV de aplicaciones de confianza (APT manual, Snap, Flatpak)
 * y lo guarda en trusted.csv en el directorio actual.
 *
 * Compilar:
 *   gcc -Wall -Wextra -o list_trusted list_trusted.c
 *
 * Ejecutar:
 *   ./list_trusted
 */

static void run_and_csv(FILE *out, const char *cmd, const char *source, int fields) {
    FILE *fp = popen(cmd, "r");
    if (!fp) {
        perror("popen");
        return;
    }
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        // Elimina salto de línea final
        line[strcspn(line, "\n")] = '\0';
        // Dependiendo de la fuente, line contiene uno o dos campos
        // fields==1: solo paquete; fields==2: paquete y versión
        char *pkg = strtok(line, " \t");
        char *ver = (fields > 1) ? strtok(NULL, " \t") : "";
        if (pkg && *pkg) {
            fprintf(out, "%s,%s,%s\n", source, pkg, ver);
        }
    }
    pclose(fp);
}

int main(void) {
    const char *csv_file = "trusted.csv";
    FILE *out = fopen(csv_file, "w");
    if (!out) {
        perror("No se pudo abrir trusted.csv para escritura");
        return EXIT_FAILURE;
    }

    // Escribir encabezado CSV
    fprintf(out, "source,package,version\n");

    // 1) Paquetes APT instalados manualmente
    run_and_csv(out, "apt-mark showmanual", "apt", 1);

    // 2) Snaps instalados (sin --format)
    run_and_csv(
        out,
        "snap list 2>/dev/null | tail -n +2 | awk '{print $1 \" \" $2}'",
        "snap",
        2
    );

    // 3) Flatpaks instalados (solo si flatpak existe)
    run_and_csv(
        out,
        "which flatpak >/dev/null 2>&1 && flatpak list --app --columns=application,branch || true",
        "flatpak",
        2
    );

    fclose(out);
    printf("CSV generado exitosamente en %s\n", csv_file);
    return EXIT_SUCCESS;
}
