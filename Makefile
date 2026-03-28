CC = gcc
CFLAGS = -Wall -Wextra -D_WIN32 -DARGON2_STATIC -maes -msse4.1 -g -O2 -I./third_party/include

SRC_DIR = src
ENCR_DIR = src/encr
STEG_DIR = src/stego
OBJ_DIR = obj

MACHINE := $(shell $(CC) -dumpmachine)
ifneq (,$(findstring x86_64,$(MACHINE)))
    BIN_DIR = ./third_party/bin_x64
    LIB_DIR = ./third_party/lib_x64
    ARCH_MSG = 64-bit
else
    BIN_DIR = ./third_party/bin_x86
    LIB_DIR = ./third_party/lib_x86
    ARCH_MSG = 32-bit
endif

LDFLAGS = -L$(LIB_DIR) -largon2 -lcrypt32 -ladvapi32

SOURCES = $(SRC_DIR)/main.c $(SRC_DIR)/stegolock.c $(STEG_DIR)/steganography.c \
          $(ENCR_DIR)/encryption.c $(SRC_DIR)/vault.c $(ENCR_DIR)/aes256gcm.c $(ENCR_DIR)/aesni.c
OBJECTS = $(addprefix $(OBJ_DIR)/, $(notdir $(SOURCES:.c=.o)))
TARGET = stegolock.exe



.PHONY: all clean run help

all: header $(OBJ_DIR) $(TARGET)
	@echo -------------------------------------------------------
	@echo [SUCCESS] $(TARGET) is ready to use!

# A really cool header ;D
header:
	@echo =======================================================
	@echo   Building StegoLock for $(ARCH_MSG)
	@echo =======================================================

$(OBJ_DIR):
	@if not exist $(OBJ_DIR) mkdir $(OBJ_DIR)

$(TARGET): $(OBJECTS)
	@echo [LD] Linking executable: $@
	@$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo [SYS] Deploying $(ARCH_MSG) argon2.dll...
	@copy /Y $(subst /,\,$(BIN_DIR))\argon2.dll .\argon2.dll > nul


$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@echo [CC] Compiling $<...
	@$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/%.o: $(ENCR_DIR)/%.c
	@echo [CC] Compiling $<...
	@$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/%.o: $(STEG_DIR)/%.c
	@echo [CC] Compiling $<...
	@$(CC) $(CFLAGS) -c $< -o $@

clean:
	@echo [CLEAN] Removing build artifacts...
	@if exist $(OBJ_DIR) rmdir /s /q $(OBJ_DIR)
	@if exist $(TARGET) del $(TARGET)
	@if exist argon2.dll del argon2.dll
	@echo [SUCCESS] Removed build artifacts
