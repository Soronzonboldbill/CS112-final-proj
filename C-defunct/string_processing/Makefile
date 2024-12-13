# Compiler
CC = gcc -O2
CFLAGS = -Wall -I/opt/homebrew/include -I/opt/homebrew/opt/openssl@3/include
LDFLAGS = -L/opt/homebrew/lib -L/opt/homebrew/opt/openssl@3/lib -levent_openssl -levent -lssl -lcrypto -lcurl

# Target executable
TARGET = process

# Source files
SRC = main.c 

# Build the target
all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

# Clean up
clean:
	rm -f $(TARGET)
