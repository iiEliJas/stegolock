#include "encryption.h"
#include "aes256gcm.h"
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <argon2.h>

#define ARGON2_MEMORY_SIZE 65540
#define ARGON2_TIME_COST 3
#define ARGON2_PARALLELISM 4



static int derive_key_argon2id(const char *password, size_t password_len,
                               const unsigned char *salt, size_t salt_len,
                               unsigned char *key, size_t key_len) {
    if (!password || password_len == 0) {
        return -1;
    }
    int result = argon2id_hash_raw(
        ARGON2_TIME_COST,
        ARGON2_MEMORY_SIZE,
        ARGON2_PARALLELISM,
        password,
        password_len,
        (uint8_t*)salt,
        salt_len,
        key,
        key_len
    );
    
    return result == ARGON2_OK ? 0 : -1;
}



// Generate random IV and salt
//
static int generate_random_bytes(unsigned char *buffer, size_t len) {
    HCRYPTPROV hProv = 0;
    
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, 0)) {
        return -1;
    }
    
    BOOL success = CryptGenRandom(hProv, (DWORD)len, buffer);
    CryptReleaseContext(hProv, 0);
    
    return success ? 0 : -1;
}



EncryptedData encrypt_data(const unsigned char *plaintext, size_t plaintext_len,
                           const char *master_password) {
    EncryptedData result;
    memset(&result, 0, sizeof(result));
    
    if (!plaintext || !master_password) {
        return result;
    }
    
    // Generate salt
    if (generate_random_bytes(result.salt, SALT_SIZE) != 0) {
        fprintf(stderr, "Error: Failed to generate random salt\n");
        return result;
    }
    
    // Derive key from password
    unsigned char key[32];
    if (derive_key_argon2id(master_password, strlen(master_password),
                            result.salt, SALT_SIZE, key, 32) != 0) {
        fprintf(stderr, "Error: Key derivation failed\n");
        return result;
    }
    
    // Generate IV
    if (generate_random_bytes(result.iv, IV_SIZE) != 0) {
        fprintf(stderr, "Error: Failed to generate random IV\n");
        secure_zero(key, 32);
        return result;
    }
    
    result.ciphertext = (unsigned char *)malloc(plaintext_len);
    if (!result.ciphertext) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        secure_zero(key, 32);
        return result;
    }
    
    // Encrypt using AES-256-GCM
    if (aes256gcm_encrypt(plaintext, plaintext_len,
                          NULL, 0,
                          key, result.iv,
                          result.ciphertext, result.tag) != 0) {
        fprintf(stderr, "Error: Encryption failed\n");
        free(result.ciphertext);
        result.ciphertext = NULL;
        secure_zero(key, 32);
        return result;
    }
    
    result.ciphertext_len = plaintext_len;
    secure_zero(key, 32);
    return result;
}

unsigned char *decrypt_data(const EncryptedData *encrypted, const char *master_password,
                            size_t *plaintext_len) {
    if (!encrypted || !master_password || !plaintext_len) {
        return NULL;
    }
    
    // Derive key from password
    unsigned char key[32];
    if (derive_key_argon2id(master_password, strlen(master_password),
                            encrypted->salt, SALT_SIZE, key, 32) != 0) {
        fprintf(stderr, "Error: Key derivation failed\n");
        secure_zero(key, 32);
        return NULL;
    }
    
    // Allocate plaintext buffer
    unsigned char *plaintext = (unsigned char *)malloc(encrypted->ciphertext_len);
    if (!plaintext) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        secure_zero(key, 32);
        return NULL;
    }
    
    unsigned char tag_copy[TAG_SIZE];
    memcpy(tag_copy, encrypted->tag, TAG_SIZE);
    
    // Decrypt using AES-256-GCM
    if (aes256gcm_decrypt(encrypted->ciphertext, encrypted->ciphertext_len,
                          NULL, 0,
                          key, encrypted->iv,
                          tag_copy, plaintext) != 0) {
        fprintf(stderr, "Error: Decryption failed - invalid password or corrupted data\n");
        free(plaintext);
        secure_zero(key, 32);
        return NULL;
    }
    
    *plaintext_len = encrypted->ciphertext_len;
    secure_zero(key, 32);
    return plaintext;
}

void free_encrypted_data(EncryptedData *encrypted) {
    if (encrypted && encrypted->ciphertext) {
        free(encrypted->ciphertext);
        encrypted->ciphertext = NULL;
    }
}
