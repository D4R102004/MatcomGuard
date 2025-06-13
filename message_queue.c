#include "message_queue.h"
#include <stdlib.h>
#include <string.h>

#define MAX_MSG_SIZE 1024

MessageQueue* mq_init() {
    MessageQueue* queue = malloc(sizeof(MessageQueue));
    if (queue) {
        queue->front = NULL;
        queue->rear = NULL;
        queue->count = 0;
    }
    return queue;
}

void mq_enqueue(MessageQueue* queue, const char* message) {
    if (!queue || !message) return;
    
    // Crear nuevo nodo
    MessageNode* newNode = malloc(sizeof(MessageNode));
    if (!newNode) return;
    
    // Reservar memoria para el mensaje (+1 para '\0')
    newNode->message = malloc(MAX_MSG_SIZE + 1);
    if (!newNode->message) {
        free(newNode);
        return;
    }
    
    // Copiar mensaje (máximo MAX_MSG_SIZE caracteres)
    strncpy(newNode->message, message, MAX_MSG_SIZE);
    newNode->message[MAX_MSG_SIZE] = '\0'; // Asegurar terminación
    newNode->next = NULL;
    
    // Encolar
    if (mq_is_empty(queue)) {
        queue->front = newNode;
    } else {
        queue->rear->next = newNode;
    }
    queue->rear = newNode;
    queue->count++;
}

char* mq_dequeue(MessageQueue* queue) {
    if (mq_is_empty(queue)) return NULL;
    
    MessageNode* temp = queue->front;
    char* message = temp->message;  // Transferir propiedad del mensaje
    
    // Actualizar cola
    queue->front = temp->next;
    if (queue->front == NULL) {
        queue->rear = NULL;
    }
    queue->count--;
    
    free(temp);  // Liberar solo el nodo (no el mensaje)
    return message;
}

bool mq_is_empty(const MessageQueue* queue) {
    return (queue == NULL) || (queue->front == NULL);
}

int mq_count(const MessageQueue* queue) {
    return (queue) ? queue->count : 0;
}

void mq_destroy(MessageQueue* queue) {
    if (!queue) return;
    
    while (!mq_is_empty(queue)) {
        char* msg = mq_dequeue(queue);
        free(msg);  // Liberar el mensaje
    }
    free(queue);
}