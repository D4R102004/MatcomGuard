// usb_scanning.h
#ifndef USB_SCANNING_H
#define USB_SCANNING_H
#include "message_queue.h"
MessageQueue* scan_directory_usb(const char *path);
void expand_tilde(const char *input_path, char *expanded_path, size_t size);

#endif