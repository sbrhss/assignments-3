# Application name
TARGET = writer

# Source files
SRC = writer.c

CFLAGS = -Wall -Werror -g
LDLIBS =
CC ?= $(CROSS_COMPILE)gcc

.PHONY: all
all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $< -o $@ $(LDLIBS)

.PHONY: clean
clean:
	rm -f $(TARGET) *.o
