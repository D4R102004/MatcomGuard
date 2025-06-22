CC=gcc
CFLAGS=-Wall -I/usr/include/openssl
LDFLAGS=-lssl -lcrypto -laudit
SCANFLAGS=-lpthread

TARGET=matguard
SRC=pesquisa/pesquisa.c
USB_SCAN=usb_scanning
USB_SRC=usb_scanning.c message_queue.c
TEST_SCRIPT=Tortuga/test_file_modification/test_monitor_usb.sh
GTK_FLAGS=$(shell pkg-config --cflags gtk+-3.0)
GTK_LIBS=$(shell pkg-config --libs gtk+-3.0)
GTK_TARGET=main
GTK_SRC=main.c usb_scanning.c message_queue.c port_scanner.c

# Test directories
TEST_USB_DIR=/tmp/test_usb_simulation
BASELINE_DIR=/tmp/usb_baselines
ALERTS_DIR=/tmp/usb_alerts
HISTORY_DIR="/tmp/old_history"

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS) -lm

# $(USB_SCAN): $(USB_SRC)
# 	$(CC) $(CFLAGS) -o $(USB_SCAN) $(USB_SRC) $(SCANFLAGS)

test: $(TARGET)
	@echo "Running USB Monitoring Test..."
	@mkdir -p $(TEST_USB_DIR)
	@mkdir -p $(BASELINE_DIR)
	@mkdir -p $(ALERTS_DIR)
	@chmod +x $(TEST_SCRIPT)
	@sudo TEST_USB_DIR=$(TEST_USB_DIR) \
		  BASELINE_DIR=$(BASELINE_DIR) \
		  ALERTS_DIR=$(ALERTS_DIR) \
		  MATGUARD_PATH=./$(TARGET) \
		  $(TEST_SCRIPT)

clean:
	rm -f $(TARGET) $(USB_SCAN)
	rm -rf $(TEST_USB_DIR) $(BASELINE_DIR) $(ALERTS_DIR)
	rm -rf $(HISTORY_DIR)




gtk: $(GTK_SRC)
	$(CC) -o $(GTK_TARGET) $(GTK_SRC) $(GTK_FLAGS) $(GTK_LIBS) -lpthread


.PHONY: all clean test