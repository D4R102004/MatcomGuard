#ifndef MESSAGE_QUEUE_H
#define MESSAGE_QUEUE_H

#include <stdbool.h>

// Estructura de un nodo de mensaje
typedef struct MessageNode {
    char* message;               // Mensaje almacenado
    struct MessageNode* next;    // Siguiente nodo en la cola
} MessageNode;

// Estructura principal de la cola
typedef struct {
    MessageNode* front;          // Frente de la cola (primer mensaje)
    MessageNode* rear;           // Final de la cola (último mensaje)
    int count;                   // Contador de mensajes
} MessageQueue;

// Inicializa una nueva cola de mensajes
MessageQueue* mq_init();

// Agrega un mensaje a la cola
void mq_enqueue(MessageQueue* queue, const char* message);

// Extrae y devuelve el siguiente mensaje (debe liberarse con free())
char* mq_dequeue(MessageQueue* queue);

// Verifica si la cola está vacía
bool mq_is_empty(const MessageQueue* queue);

// Obtiene el número de mensajes en cola
int mq_count(const MessageQueue* queue);

// Libera todos los recursos de la cola
void mq_destroy(MessageQueue* queue);

#endif // MESSAGE_QUEUE_H