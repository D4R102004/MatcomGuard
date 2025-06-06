#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <time.h>
#include <gtk/gtk.h>
extern void scan_directory(const char *path);
extern void expand_tilde(const char *input_path, char *expanded_path, size_t size);

static gchar *texto_ingresado = NULL; // Variable global para almacenar el texto
static GtkWidget *text_view;  // Declaración global

//Funcion para printear texto
void append_to_console(const gchar *text) {
    GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_view));
    GtkTextIter end;
    
    gtk_text_buffer_get_end_iter(buffer, &end);
    gtk_text_buffer_insert(buffer, &end, text, -1);
    
    // Auto-scroll
    gtk_text_view_scroll_to_iter(GTK_TEXT_VIEW(text_view), &end, 0.0, FALSE, 0.0, 1.0);
}


static void funcion_boton1() {
    if (texto_ingresado != NULL) {
        char message[256];
        snprintf(message, sizeof(message), "Analizando: %s\n", texto_ingresado);
        append_to_console(message);
        
        char expanded_path[1024];
        expand_tilde(texto_ingresado, expanded_path, sizeof(expanded_path));
        
        // Redirige stdout a la consola
        DIR *dir = opendir(expanded_path);
        if (!dir) {
            append_to_console("Error: No se pudo abrir el directorio\n");
            return;
        }
        
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) 
                continue;
                
            char file_info[512];
            snprintf(file_info, sizeof(file_info), "Archivo: %s\n", entry->d_name);
            append_to_console(file_info);
        }
        closedir(dir);
    } else {
        append_to_console("Error: No se ingresó ruta\n");
    }
}

static void funcion_boton2() {

}

static void funcion_boton3() {

}

static void button_clicked(GtkWidget *widget, gpointer data) {
    const gchar *boton_presionado = (char*)data;
    
    if (g_strcmp0(boton_presionado, "1") == 0) {
        funcion_boton1();
    } 
    else if (g_strcmp0(boton_presionado, "2") == 0) {
        funcion_boton2();
    } 
    else if (g_strcmp0(boton_presionado, "3") == 0) {
        funcion_boton3();
    }
}

static void on_entry_activate(GtkEntry *entry, gpointer user_data) {
    // Liberar memoria si ya había texto almacenado
    if (texto_ingresado != NULL) {
        g_free(texto_ingresado);
    }
    
    // Obtener y guardar el nuevo texto
    const gchar *text = gtk_entry_get_text(entry);
    texto_ingresado = g_strdup(text); // g_strdup hace una copia del texto
    
    g_print("Texto guardado: %s\n", texto_ingresado);
}

static void on_entry_changed(GtkEntry *entry, gpointer user_data) {
    // Opcional: también puedes actualizar la variable mientras se escribe
    if (texto_ingresado != NULL) {
        g_free(texto_ingresado);
    }
    texto_ingresado = g_strdup(gtk_entry_get_text(entry));
}

static void activate(GtkApplication *app, gpointer user_data) {
    // Crear ventana principal
    GtkWidget *window = gtk_application_window_new(app);
    gtk_window_set_title(GTK_WINDOW(window), "MatcomGuard");
    gtk_window_set_default_size(GTK_WINDOW(window), 400, 300);
    
    // Crear contenedor principal
    GtkWidget *main_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_container_add(GTK_CONTAINER(window), main_box);
    
    // Aplicar CSS (igual que antes)
    GtkCssProvider *provider = gtk_css_provider_new();
    gtk_css_provider_load_from_data(provider,
        "window.background {"
        "   background-image: url('./image.jpg');"
        "   background-size: cover;"
        "}"
        "box {"
        "   background-color: rgba(38, 33, 78, 0.5);"
        "}"
        "button {"
        "   border: none;"
        "   outline: none;"
        "   box-shadow: none;"
        "   background-color: rgba(9, 132, 227, 0.8);"
        "   color: white;"
        "   font-weight: bold;"
        "}"
        "entry {"
        "   background-color: rgba(255, 255, 255, 0.8);"
        "   color: #2d3436;"
        "   padding: 8px;"
        "   border-radius: 4px;"
        "   border: 1px solid #636e72;"
        "}", -1, NULL);
    
    GtkStyleContext *context = gtk_widget_get_style_context(window);
    gtk_style_context_add_provider(context, 
        GTK_STYLE_PROVIDER(provider), 
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    
    // Añadir espacio flexible arriba
    GtkWidget *top_spacer = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_box_pack_start(GTK_BOX(main_box), top_spacer, TRUE, TRUE, 0);
    
    // Crear contenedor para los elementos
    GtkWidget *content_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_box_pack_start(GTK_BOX(main_box), content_box, FALSE, FALSE, 0);
    gtk_container_set_border_width(GTK_CONTAINER(content_box), 20);
    
    // Crear caja de texto (Entry)
    GtkWidget *entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(entry), "Escribe algo aquí...");
    gtk_widget_set_size_request(entry, 200, 40);
    gtk_widget_set_halign(entry, GTK_ALIGN_CENTER);
    
    // Conectar señales
    g_signal_connect(entry, "activate", G_CALLBACK(on_entry_activate), NULL);
    g_signal_connect(entry, "changed", G_CALLBACK(on_entry_changed), NULL);
    
    // Crear botones (igual que antes)
    GtkWidget *button1 = gtk_button_new_with_label("Analizar Dispositivo USB");
    GtkWidget *button2 = gtk_button_new_with_label("Botón 2");
    GtkWidget *button3 = gtk_button_new_with_label("Botón 3");
    
    gtk_widget_set_size_request(button1, 200, 40);
    gtk_widget_set_size_request(button2, 200, 40);
    gtk_widget_set_size_request(button3, 200, 40);
    
    g_signal_connect(button1, "clicked", G_CALLBACK(button_clicked), "1");
    g_signal_connect(button2, "clicked", G_CALLBACK(button_clicked), "2");
    g_signal_connect(button3, "clicked", G_CALLBACK(button_clicked), "3");
    
    gtk_widget_set_halign(button1, GTK_ALIGN_CENTER);
    gtk_widget_set_halign(button2, GTK_ALIGN_CENTER);
    gtk_widget_set_halign(button3, GTK_ALIGN_CENTER);
    
    // Añadir elementos al box
    gtk_box_pack_start(GTK_BOX(content_box), entry, FALSE, FALSE, 5);
    gtk_box_pack_start(GTK_BOX(content_box), button1, FALSE, FALSE, 5);
    gtk_box_pack_start(GTK_BOX(content_box), button2, FALSE, FALSE, 5);
    gtk_box_pack_start(GTK_BOX(content_box), button3, FALSE, FALSE, 5);
    
    //Printear Texto
    // Crear el área de texto con scroll
    GtkWidget *scrolled_window = gtk_scrolled_window_new(NULL, NULL);
    text_view = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(text_view), FALSE);  // Solo lectura
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(text_view), TRUE);  // Fuente monoespaciada
    gtk_container_add(GTK_CONTAINER(scrolled_window), text_view);
    gtk_box_pack_start(GTK_BOX(content_box), scrolled_window, TRUE, TRUE, 5);
    gtk_widget_set_size_request(scrolled_window, -1, 150);  // Altura fija

    gtk_widget_show_all(window);
}


int main(int argc, char **argv) {
    GtkApplication *app;
    int status;
    
    app = gtk_application_new("com.example.matcomguard", G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(app, "activate", G_CALLBACK(activate), NULL);
    status = g_application_run(G_APPLICATION(app), argc, argv);
    
    // Liberar memoria al cerrar la aplicación
    if (texto_ingresado != NULL) {
        g_free(texto_ingresado);
    }
    
    g_object_unref(app);
    
    return status;
}