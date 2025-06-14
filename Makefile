CC=gcc
CFLAGS=-Wall -I/usr/include/openssl
LDFLAGS=-lssl -lcrypto

TARGET=matguard
SRC=pesquisa/pesquisa.c
USB_SCAN=usb_scanning
USB_SRC=USB_Scanning/usb_scanning.c
TEST_SCRIPT=Tortuga/test_file_modification/test_monitor_usb.sh

# Test directories
TEST_USB_DIR=/tmp/test_usb_simulation
BASELINE_DIR=/tmp/usb_baselines
ALERTS_DIR=/tmp/usb_alerts

all: $(TARGET) $(USB_SCAN)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS) -lm

$(USB_SCAN): $(USB_SRC)
	$(CC) -o $(USB_SCAN) $(USB_SRC)

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

.PHONY: all clean test