#ifndef AES256GCM
#define AES256GCM

#include <stdint.h>
#include <stddef.h>
 
#define AES256GCM_KEY_SIZE 32   // bytes
#define AES256GCM_IV_SIZE  12   // 96-bit IV
#define AES256GCM_TAG_SIZE 16   // 128-bit authentication tag
 

void secure_zero(void *buf, size_t len);



// Encrypt plaintext and produce an authentication tag
//
// in        - plaintext
// in_len    - plaintext length in bytes
// aad       - additional authenticated data
// aad_len   - AAD length in bytes (can be 0)
// key       - AES-256 key
// iv        - 12-byte IV
// out       - ciphertext output
// tag       - 16-byte tag 
//
//  Returns 0 on success
int aes256gcm_encrypt(const uint8_t  *in, size_t in_len, const uint8_t  *aad, size_t aad_len,
                      const uint8_t key[AES256GCM_KEY_SIZE], const uint8_t iv[AES256GCM_IV_SIZE],
                      uint8_t *out, uint8_t tag[AES256GCM_TAG_SIZE]);


 
                      
// Decrypt ciphertext and verify the authentication tag.
//
// in        - ciphertext
// in_len    - ciphertext length in bytes
// aad       - additional authenticated data
// aad_len   - AAD length in bytes (can be 0)
// key       - AES-256 key
// iv        - 12-byte IV
// out       - plaintext output
// tag       - 16-byte tag 
//
// Returns 0 on success
// Returns -1 on failure
int aes256gcm_decrypt(const uint8_t  *in, size_t in_len, const uint8_t  *aad, size_t aad_len,
                      const uint8_t key[AES256GCM_KEY_SIZE], const uint8_t iv[AES256GCM_IV_SIZE],
                      uint8_t tag[AES256GCM_TAG_SIZE], uint8_t *out);

#endif //AES256GCM
