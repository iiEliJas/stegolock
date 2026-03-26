#ifndef AESNI_CORE
#define AESNI_CORE

#include <stdint.h>
#include <string.h>
#include <wmmintrin.h>

typedef enum{
        AESNI_128 = 4,
        AESNI_256 = 8
} AESNI_KEYSIZE;


typedef struct{
        __m128i keys[15];      // round keys
        int nr;               // number of rounds (10,12,14)
} AESNI_Ctx;




// Init function - setup for aes_encrypt
// takes in AES_Ctx pointer, which will be passed into aes_encrypt
//
void aesni_init(const uint8_t *key, AESNI_KEYSIZE keysize, AESNI_Ctx *ctx);




// AESNI encryption
// takes in a message (in) and outputs a cipher (out)
// AESNI_Ctx must be initialized beforehand
//
void aesni_encrypt(const uint8_t in[16], uint8_t out[16], const AESNI_Ctx *ctx);




// AESNI decryption 
// takes in a cipher (in) and outputs the encrypted message (out)
// AESNI_Ctx must be initialized beforehand
//
void aesni_decrypt(const uint8_t in[16], uint8_t out[16], const AESNI_Ctx *ctx);





////////////////////////////////////////////////////////////////////////////////////////
///                     MODES
///


//ECB — Electronic Codebook
//Each block is encrypted independently with the same key
//
void aesni_ecb_encrypt(const uint8_t *in, uint8_t *out, int num_blocks, const AESNI_Ctx *ctx);
void aesni_ecb_decrypt(const uint8_t *in, uint8_t *out, int num_blocks, const AESNI_Ctx *ctx);



//CBC — Cipher Block Chaining
//Each plaintext block is XORed with the previous ciphertext block before encryption
//
void aesni_cbc_encrypt(const uint8_t *in, uint8_t *out, int num_blocks, const AESNI_Ctx *ctx, const uint8_t iv[16]);
void aesni_cbc_decrypt(const uint8_t *in, uint8_t *out, int num_blocks, const AESNI_Ctx *ctx, const uint8_t iv[16]);



//CTR — Counter Mode
//Encrypts a nonce/counter value and XORs the result with plaintext
//
void aesni_ctr_encrypt(const uint8_t *in, uint8_t *out, int num_blocks, const AESNI_Ctx *ctx, const uint8_t nonce[16]);
void aesni_ctr_decrypt(const uint8_t *in, uint8_t *out, int num_blocks, const AESNI_Ctx *ctx, const uint8_t nonce[16]);


#endif  //AESNI_CORE
