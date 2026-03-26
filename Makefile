CC = gcc
CFLAGS = -Wall -Wextra -D_WIN32 -maes -msse4.1 -g -O2 -I./include

SRC_DIR = src
ENCR_DIR = src/encr
STEG_DIR = src/stego
OBJ_DIR = obj

SOURCES = $(SRC_DIR)/main.c $(SRC_DIR)/stegolock.c $(STEG_DIR)/steganography.c $(ENCR_DIR)/encryption.c $(SRC_DIR)/vault.c $(ENCR_DIR)/aes256gcm.c $(ENCR_DIR)/aesni.c

OBJECTS = $(addprefix $(OBJ_DIR)/, $(notdir $(SOURCES:.c=.o)))

TARGET = stegolock



.PHONY: all clean run help

all: $(OBJ_DIR) $(TARGET)

$(OBJ_DIR):
	@if not exist $(OBJ_DIR) mkdir $(OBJ_DIR)



$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ ./lib/argon2.lib -lcrypt32
	@echo "Build complete: $(TARGET)"

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/%.o: $(ENCR_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/%.o: $(STEG_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@



clean:
	@if exist $(OBJ_DIR) rmdir /s /q $(OBJ_DIR)
	@if exist $(TARGET) del $(TARGET)
	@echo Cleaned build artifacts
