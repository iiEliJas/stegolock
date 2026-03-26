#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <stdint.h>
#include <stddef.h>

#define SALT_SIZE 16
#define IV_SIZE 12
#define TAG_SIZE 16


typedef struct {
    unsigned char salt[SALT_SIZE];
    unsigned char iv[IV_SIZE];
    unsigned char tag[TAG_SIZE];
    unsigned char *ciphertext;
    size_t ciphertext_len;
} EncryptedData;

// Encrypt data with AES-256-GCM
// Returns EncryptedData structure (caller must free ciphertext)
// Returns with NULL=ciphertext on failure
EncryptedData encrypt_data(const unsigned char *plaintext, size_t plaintext_len,
                           const char *master_password);

// Decrypt data with AES-256-GCM
// Returns plaintext on success, NULL on failure
// Sets plaintext_len to decrypted size
unsigned char *decrypt_data(const EncryptedData *encrypted, const char *master_password,
                            size_t *plaintext_len);

// Free encrypted data structure
void free_encrypted_data(EncryptedData *encrypted);

#endif // ENCRYPTION_H
