CC=gcc
CFLAGS=-Wall -I/usr/include/openssl
LDFLAGS=-lssl -lcrypto

# Nombre del ejecutable
TARGET=matguard

# Ruta del archivo fuente
SRC=pesquisa/pesquisa.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean