# ConfD CDB callback build for FastAPI DPDK
#
# Prerequisites:
#   - ConfD developer kit (confd-distro) installed
#   - CONFD_DIR environment variable set to ConfD installation root
#
# Usage:
#   make                  # Build the callback daemon
#   make install          # Install to CONFD_DIR
#   make clean            # Remove build artifacts

CONFD_DIR ?= /opt/confd
CC = gcc
CFLAGS = -Wall -Wextra -Werror -O2 -I$(CONFD_DIR)/include
LDFLAGS = -L$(CONFD_DIR)/lib -lconfd

TARGET = fastapi_confd
SRC = fastapi_confd.c

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

install: $(TARGET)
	cp $(TARGET) $(CONFD_DIR)/bin/
	chmod +x $(CONFD_DIR)/bin/$(TARGET)
	@echo "Installed $(TARGET) to $(CONFD_DIR)/bin/"

clean:
	rm -f $(TARGET)
