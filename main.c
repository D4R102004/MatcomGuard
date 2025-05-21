#include <gtk/gtk.h>

static void button_clicked(GtkWidget *widget, gpointer data) {
    g_print("Botón %s presionado\n", (char*)data);
}

static void activate(GtkApplication *app, gpointer user_data) {
    // Crear ventana principal
    GtkWidget *window = gtk_application_window_new(app);
    gtk_window_set_title(GTK_WINDOW(window), "MatcomGuard");
    gtk_window_set_default_size(GTK_WINDOW(window), 400, 300);
    
    // Crear contenedor principal
    GtkWidget *main_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_container_add(GTK_CONTAINER(window), main_box);
    
    // Aplicar CSS para el fondo
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
        "}", -1, NULL);
    
    // Aplicar el CSS a la ventana
    GtkStyleContext *context = gtk_widget_get_style_context(window);
    gtk_style_context_add_provider(context, 
        GTK_STYLE_PROVIDER(provider), 
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    
    // Resto del código sin cambios...
    // Añadir espacio flexible arriba
    GtkWidget *top_spacer = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_box_pack_start(GTK_BOX(main_box), top_spacer, TRUE, TRUE, 0);
    
    // Crear contenedor para los botones
    GtkWidget *button_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_box_pack_start(GTK_BOX(main_box), button_box, FALSE, FALSE, 0);
    gtk_container_set_border_width(GTK_CONTAINER(button_box), 20);
    
    // Crear botones
    GtkWidget *button1 = gtk_button_new_with_label("Botón 1");
    GtkWidget *button2 = gtk_button_new_with_label("Botón 2");
    GtkWidget *button3 = gtk_button_new_with_label("Botón 3");
    
    // Tamaño de los botones
    gtk_widget_set_size_request(button1, 200, 40);
    gtk_widget_set_size_request(button2, 200, 40);
    gtk_widget_set_size_request(button3, 200, 40);
    
    // Conectar señales de clic
    g_signal_connect(button1, "clicked", G_CALLBACK(button_clicked), "1");
    g_signal_connect(button2, "clicked", G_CALLBACK(button_clicked), "2");
    g_signal_connect(button3, "clicked", G_CALLBACK(button_clicked), "3");
    
    // Centrar horizontalmente los botones
    gtk_widget_set_halign(button1, GTK_ALIGN_CENTER);
    gtk_widget_set_halign(button2, GTK_ALIGN_CENTER);
    gtk_widget_set_halign(button3, GTK_ALIGN_CENTER);
    
    // Añadir botones al box
    gtk_box_pack_start(GTK_BOX(button_box), button1, FALSE, FALSE, 5);
    gtk_box_pack_start(GTK_BOX(button_box), button2, FALSE, FALSE, 5);
    gtk_box_pack_start(GTK_BOX(button_box), button3, FALSE, FALSE, 5);
    
    // Mostrar todos los elementos
    gtk_widget_show_all(window);
}

int main(int argc, char **argv) {
    GtkApplication *app;
    int status;
    
    app = gtk_application_new("com.example.matcomguard", G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(app, "activate", G_CALLBACK(activate), NULL);
    status = g_application_run(G_APPLICATION(app), argc, argv);
    g_object_unref(app);
    
    return status;
}