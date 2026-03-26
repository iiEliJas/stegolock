#include "aesni.h"


//////////////////////////////////////////////////////////////////
///             ASSISTORS
///             

// Applies one key schedule round for AESNI_128
//
static inline __m128i keyassist128(__m128i key, __m128i result){
    result = _mm_shuffle_epi32(result, 0xFF);

    __m128i tmp = _mm_slli_si128(key,4);
    key = _mm_xor_si128(key, tmp);

    tmp = _mm_slli_si128(key,4);
    key = _mm_xor_si128(key, tmp);

    tmp = _mm_slli_si128(key,4);
    key = _mm_xor_si128(key, tmp);

    return _mm_xor_si128(key, result);
}




// Assist for key schedule for AESNI-256
static inline __m128i keyassist256_1(__m128i key, __m128i result){
    result = _mm_shuffle_epi32(result, 0xFF);

    __m128i tmp = _mm_slli_si128(key, 4);
    
    key = _mm_xor_si128(key, tmp);
    tmp  = _mm_slli_si128(tmp, 4);
    key = _mm_xor_si128(key, tmp);
    tmp  = _mm_slli_si128(tmp, 4);
    key = _mm_xor_si128(key, tmp);

    return _mm_xor_si128(key, result);
}
 
static inline __m128i keyassist256_2(__m128i key1, __m128i key2){
    __m128i result = _mm_aeskeygenassist_si128(key1, 0x00);
    result = _mm_shuffle_epi32(result, 0xAA);
    
    __m128i tmp = _mm_slli_si128(key2, 4);
    key2 = _mm_xor_si128(key2, tmp);
    tmp  = _mm_slli_si128(tmp, 4);
    key2 = _mm_xor_si128(key2, tmp);
    tmp  = _mm_slli_si128(tmp, 4);
    key2 = _mm_xor_si128(key2, tmp);
    return _mm_xor_si128(key2, result);
}



//////////////////////////////////////////////////////////////////
///             KEY EXPANSION
///             


static void aes128_key_expansion(const uint8_t *key, __m128i *enc_keys){
    enc_keys[0]  = _mm_loadu_si128((__m128i*)key);
 
    enc_keys[ 1] = keyassist128(enc_keys[ 0], _mm_aeskeygenassist_si128(enc_keys[ 0], 0x01));
    enc_keys[ 2] = keyassist128(enc_keys[ 1], _mm_aeskeygenassist_si128(enc_keys[ 1], 0x02));
    enc_keys[ 3] = keyassist128(enc_keys[ 2], _mm_aeskeygenassist_si128(enc_keys[ 2], 0x04));
    enc_keys[ 4] = keyassist128(enc_keys[ 3], _mm_aeskeygenassist_si128(enc_keys[ 3], 0x08));
    enc_keys[ 5] = keyassist128(enc_keys[ 4], _mm_aeskeygenassist_si128(enc_keys[ 4], 0x10));
    enc_keys[ 6] = keyassist128(enc_keys[ 5], _mm_aeskeygenassist_si128(enc_keys[ 5], 0x20));
    enc_keys[ 7] = keyassist128(enc_keys[ 6], _mm_aeskeygenassist_si128(enc_keys[ 6], 0x40));
    enc_keys[ 8] = keyassist128(enc_keys[ 7], _mm_aeskeygenassist_si128(enc_keys[ 7], 0x80));
    enc_keys[ 9] = keyassist128(enc_keys[ 8], _mm_aeskeygenassist_si128(enc_keys[ 8], 0x1b));
    enc_keys[10] = keyassist128(enc_keys[ 9], _mm_aeskeygenassist_si128(enc_keys[ 9], 0x36));
}




static void aes256_key_expansion(const uint8_t *key, __m128i *enc_keys){
    enc_keys[0] = _mm_loadu_si128((__m128i*)key);
    enc_keys[1] = _mm_loadu_si128((__m128i*)(key + 16));
 
    enc_keys[2] = keyassist256_1(enc_keys[ 0], _mm_aeskeygenassist_si128(enc_keys[ 1], 0x01));
    enc_keys[3] = keyassist256_2(enc_keys[ 2], enc_keys[ 1]);
    
    enc_keys[4] = keyassist256_1(enc_keys[ 2], _mm_aeskeygenassist_si128(enc_keys[ 3], 0x02));
    enc_keys[5] = keyassist256_2(enc_keys[ 4], enc_keys[ 3]);

    enc_keys[6] = keyassist256_1(enc_keys[ 4], _mm_aeskeygenassist_si128(enc_keys[ 5], 0x04));
    enc_keys[7] = keyassist256_2(enc_keys[ 6], enc_keys[ 5]);
    
    enc_keys[8] = keyassist256_1(enc_keys[ 6], _mm_aeskeygenassist_si128(enc_keys[ 7], 0x08));
    enc_keys[9] = keyassist256_2(enc_keys[ 8], enc_keys[ 7]);

    enc_keys[10] = keyassist256_1(enc_keys[ 8], _mm_aeskeygenassist_si128(enc_keys[ 9], 0x10));
    enc_keys[11] = keyassist256_2(enc_keys[10], enc_keys[ 9]);

    enc_keys[12] = keyassist256_1(enc_keys[10], _mm_aeskeygenassist_si128(enc_keys[11], 0x20));
    enc_keys[13] = keyassist256_2(enc_keys[12], enc_keys[11]);

    enc_keys[14] = keyassist256_1(enc_keys[12], _mm_aeskeygenassist_si128(enc_keys[13], 0x40));
}




//////////////////////////////////////////////////////////////////
///             INIT, ENCRYPT AND DECRYPT
///             

void aesni_init(const uint8_t *key, AESNI_KEYSIZE keysize, AESNI_Ctx *ctx){
    ctx->nr = (int)keysize + 6;   // 10, 12, or 14
 
    switch (keysize){
        case AESNI_128: aes128_key_expansion(key, ctx->keys); break;
        case AESNI_256: aes256_key_expansion(key, ctx->keys); break;
    }
}
 
 
void aesni_encrypt(const uint8_t in[16], uint8_t out[16], const AESNI_Ctx *ctx){
    __m128i block = _mm_loadu_si128((__m128i*)in);
 
    block = _mm_xor_si128(block, ctx->keys[0]);           // AddRoundKey
 
    for (int i = 1; i < ctx->nr; i++){
        block = _mm_aesenc_si128(block, ctx->keys[i]);    // rounds 1 to Nr-1
    }
 
    block = _mm_aesenclast_si128(block, ctx->keys[ctx->nr]); // final round
 
    _mm_storeu_si128((__m128i*)out, block);
}
 
 
void aesni_decrypt(const uint8_t in[16], uint8_t out[16], const AESNI_Ctx *ctx){
    __m128i block = _mm_loadu_si128((__m128i*)in);
 
    block = _mm_xor_si128(block, ctx->keys[ctx->nr]);     // AddRoundKey 
 
    for (int i = ctx->nr - 1; i > 0; i--){
        block = _mm_aesdec_si128(block, _mm_aesimc_si128(ctx->keys[i]));
    }
 
    block = _mm_aesdeclast_si128(block, ctx->keys[0]);    // final round
 
    _mm_storeu_si128((__m128i*)out, block);
}




//////////////////////////////////////////////////////////////////
///             MODES
///             

// ECB — Electronic Codebook
// Every block is encrypted independently with the same key
//
void aesni_ecb_encrypt(const uint8_t *in, uint8_t *out, int num_blocks, const AESNI_Ctx *ctx){
    for (int i = 0; i < num_blocks; i++){
        aesni_encrypt(in + i*16, out + i*16, ctx);
    }
}
 
void aesni_ecb_decrypt(const uint8_t *in, uint8_t *out, int num_blocks, const AESNI_Ctx *ctx){
    for (int i = 0; i < num_blocks; i++){
        aesni_decrypt(in + i*16, out + i*16, ctx);
    }
}
 
 
// CBC — Cipher Block Chaining
//
// Encrypt: cipher[i] = AES_enc(plaintext[i] XOR cipher[i-1]) 
// Decrypt: plaintext[i]  = AES_dec(cipher[i]) XOR cipher[i-1]
//
void aesni_cbc_encrypt(const uint8_t *in, uint8_t *out, int num_blocks, const AESNI_Ctx *ctx, const uint8_t iv[16]){
    __m128i prev = _mm_loadu_si128((__m128i*)iv);
 
    for (int i = 0; i < num_blocks; i++){
        __m128i block = _mm_loadu_si128((__m128i*)(in + i*16));
        block = _mm_xor_si128(block, prev);                   // XOR with prev cipher
 
        block = _mm_xor_si128(block, ctx->keys[0]);
        for (int r = 1; r < ctx->nr; r++)
            block = _mm_aesenc_si128(block, ctx->keys[r]);
        block = _mm_aesenclast_si128(block, ctx->keys[ctx->nr]);
 
        _mm_storeu_si128((__m128i*)(out + i*16), block);
        prev = block;
    }
}
 
void aesni_cbc_decrypt(const uint8_t *in, uint8_t *out, int num_blocks, const AESNI_Ctx *ctx, const uint8_t iv[16]){
    __m128i prev = _mm_loadu_si128((__m128i*)iv);
 
    for (int i = 0; i < num_blocks; i++){
        __m128i cipher = _mm_loadu_si128((__m128i*)(in + i*16));
        __m128i block  = cipher;
 
        block = _mm_xor_si128(block, ctx->keys[ctx->nr]);
        for (int r = ctx->nr - 1; r > 0; r--)
            block = _mm_aesdec_si128(block, _mm_aesimc_si128(ctx->keys[r]));
        block = _mm_aesdeclast_si128(block, ctx->keys[0]);
 
        block = _mm_xor_si128(block, prev);                   // XOR with prev cipher 
        _mm_storeu_si128((__m128i*)(out + i*16), block);
        prev = cipher; 
    }
}
 
 
// CBC — Cipher Block Chaining
//
// keystream[i] = AES_enc(nonce + i) 
// ciphertext   = plaintext XOR keystream
// Encrypt and Decrypt are the same 
//
// Nonce/counter layout (standard 128-bit):
//
 
static inline __m128i ctr_increment(__m128i counter){
    uint8_t buf[16];
    _mm_storeu_si128((__m128i*)buf, counter);
 
    // Walk from the last byte backwards
    for (int i = 15; i >= 0; i--){
        if (++buf[i] != 0) break;
    }
 
    return _mm_loadu_si128((__m128i*)buf);
}
 
static void aesni_ctr(const uint8_t *in, uint8_t *out, int num_blocks, const AESNI_Ctx *ctx, const uint8_t nonce[16]){
    __m128i counter = _mm_loadu_si128((__m128i*)nonce);
 
    for (int i = 0; i < num_blocks; i++){
        // Encrypt the counter 
        __m128i ks = counter;
        ks = _mm_xor_si128(ks, ctx->keys[0]);
        for (int r = 1; r < ctx->nr; r++){
            ks = _mm_aesenc_si128(ks, ctx->keys[r]);
        }
        ks = _mm_aesenclast_si128(ks, ctx->keys[ctx->nr]);
 
        // XOR plaintext or ciphertext with keystream
        __m128i data = _mm_loadu_si128((__m128i*)(in + i*16));
        _mm_storeu_si128((__m128i*)(out + i*16), _mm_xor_si128(data, ks));
 
        counter = ctr_increment(counter);
    }
}
 
void aesni_ctr_encrypt(const uint8_t *in, uint8_t *out, int num_blocks, const AESNI_Ctx *ctx, const uint8_t nonce[16]){
    aesni_ctr(in, out, num_blocks, ctx, nonce);
}
 
void aesni_ctr_decrypt(const uint8_t *in, uint8_t *out, int num_blocks, const AESNI_Ctx *ctx, const uint8_t nonce[16]){
    aesni_ctr(in, out, num_blocks, ctx, nonce);
}



