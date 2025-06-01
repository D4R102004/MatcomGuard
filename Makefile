CC=gcc
CFLAGS=-Wall -I/usr/include/openssl
LDFLAGS=-lssl -lcrypto

# Nombre del ejecutable
TARGET=matguard

# Ruta del archivo fuente
SRC=pesquisa/pesquisa.c
USB_SCAN=usb_scanning
USB_SRC=USB_Scanning/usb_scanning.c
LIST=/tmp/scanned_usb.list

all: $(TARGET) $(USB_SCAN)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

$(USB_SCAN): $(USB_SRC)
	$(CC) -o $(USB_SCAN) $(USB_SRC)

clean:
	rm -f $(TARGET) $(USB_SCAN) $(LIST)

.PHONY: all clean
