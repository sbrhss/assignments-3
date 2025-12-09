# Application name
TARGET = aesdsocket

# Source files
SRC = aesdsocket.c

CFLAGS = -Wall -Werror -g
LDLIBS =
CC ?= $(CROSS_COMPILE)gcc

.PHONY: all default
all: $(TARGET)
default: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $< -o $@ $(LDLIBS)

.PHONY: clean
clean:
	rm -f $(TARGET) *.o
