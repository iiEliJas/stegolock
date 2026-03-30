#include "aes256gcm.h"
#include "aesni.h"
#include <string.h>
#include <stdint.h>


//////////////////////////////////////////////////////////////////
///             HELPERS
/// 

// Zero memory without compiler optimization
//
void secure_zero(void *buf, size_t len){
    volatile uint8_t *p = (volatile uint8_t *)buf;
    for (size_t i=0; i < len; i++){
        p[i] = 0;
    }
}
 

// byte comparison
//
static int my_memcmp(const uint8_t *a, const uint8_t *b, size_t len){
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++){
        diff |= a[i] ^ b[i];
    }
    return diff;   // 0 if equal
}
 

// Puts a uint64_t into a uint8_t array
//
static void b64_to_b8(uint8_t out[8], uint64_t val){
    for (int i = 7; i >= 0; i--){
        out[i] = (uint8_t)(val & 0xFF);
        val >>= 8;
    }
}



//////////////////////////////////////////////////////////////////
///             GHASH
///

//  GF(2^128) multiplication
//  Algorithm 1 from NIST SP 800-38D.
//
static void gmul(const uint8_t X[16], const uint8_t Y[16], uint8_t out[16]){
    uint8_t Z[16] = {0};
    uint8_t V[16];
    memcpy(V, X, 16);
 
    for (int i = 0; i < 16; i++){
        for (int j = 7; j >= 0; j--){
            // Only if bit (7-j) of Y[i] is set -> XOR V into Z
            if (Y[i] & (1 << j)){
                for (int k = 0; k < 16; k++) Z[k] ^= V[k];
            }
 
            // Right shift V by 1 bit and reduce if last bit was set
            uint8_t temp = V[15] & 1;
            for (int k = 15; k > 0; k--){
                V[k] = (uint8_t)((V[k] >> 1) | (V[k-1] << 7));
            }
            V[0] >>= 1;
            // Reduction polynomial is 0xe1
            if (temp) V[0] ^= 0xe1;
        }
    }
 
    memcpy(out, Z, 16);
}


// GHASH update function
// Y = (Y XOR data) * H
//
static void ghash_update(uint8_t Y[16], const uint8_t H[16], const uint8_t *data, size_t len){
    uint8_t block[16];
 
    // 16 byte blocks
    size_t i = 0;
    for (; i + 16 <= len; i += 16){
        for (int k = 0; k < 16; k++) block[k] = Y[k] ^ data[i + k];
        gmul(block, H, Y);
    }
 
    // Partial last block 
    if (i < len){
        memset(block, 0, 16);
        memcpy(block, data + i, len - i);
        for (int k = 0; k < 16; k++) block[k] ^= Y[k];
        gmul(block, H, Y);
    }
 
    secure_zero(block, 16);
}




//////////////////////////////////////////////////////////////////
///             GCM
///

// Increment bytes
// Start at the least significant byte and carry left
//
static void gcm_incr32(uint8_t counter[16]){
    for (int i = 15; i >= 12; i--){
        counter[i]++;
        if (counter[i] != 0) break;
    }
}


static void gcm_ctr(const uint8_t *in, uint8_t *out, size_t len, const AESNI_Ctx *ctx, uint8_t counter[16]){
    uint8_t keystream[16];
 
    // Full 16 byte blocks
    size_t i = 0;
    for (; i + 16 <= len; i += 16){
        aesni_encrypt(counter, keystream, ctx);
        gcm_incr32(counter);
        for (int j = 0; j < 16; j++)
            out[i + j] = in[i + j] ^ keystream[j];
    }
 
    // Partial last block
    if (i < len){
        aesni_encrypt(counter, keystream, ctx);
        for (size_t j = 0; j < len - i; j++)
            out[i + j] = in[i + j] ^ keystream[j];
    }
 
    secure_zero(keystream, 16);
}


 // GCM tag
 // NIST SP 800-38D section 7.1
 // S = GHASH_H(AAD || pad || CT || pad || [len(AAD)]64 || [len(CT)]64)
 // T = AES_K(J0) XOR S
 //
static void gcm_compute_tag(uint8_t tag[16], const uint8_t H[16], const uint8_t J0[16], const uint8_t *aad, size_t aad_len,
                            const uint8_t *ct,  size_t ct_len, const AESNI_Ctx *ctx){
    uint8_t Y[16] = {0};
 
    // Hash the AAD
    ghash_update(Y, H, aad, aad_len);
 
    // Hash the ciphertext
    ghash_update(Y, H, ct, ct_len);
 
    // Hash the length block: [len(AAD) bits]64 || [len(CT) bits]64
    uint8_t len_block[16];
    b64_to_b8(len_block+0, (uint64_t)aad_len*8);
    b64_to_b8(len_block+8, (uint64_t)ct_len*8);
    ghash_update(Y, H, len_block, 16);
 
    // Tag = E_K(J0) XOR S
    uint8_t EJ0[16];
    aesni_encrypt(J0, EJ0, ctx);
    for (int i = 0; i < 16; i++) tag[i] = EJ0[i] ^ Y[i];
 
    secure_zero(Y, 16);
    secure_zero(EJ0, 16);
    secure_zero(len_block, 16);
}



//////////////////////////////////////////////////////////////////
///             AES256-GCM
///

int aes256gcm_encrypt(const uint8_t  *in, size_t in_len, const uint8_t  *aad, size_t aad_len,
                      const uint8_t key[AES256GCM_KEY_SIZE], const uint8_t iv[AES256GCM_IV_SIZE],
                      uint8_t *out, uint8_t tag[AES256GCM_TAG_SIZE]){
    AESNI_Ctx ctx;
    aesni_init(key, AESNI_256, &ctx);
 
    // H = AES_K(0)
    uint8_t H[16] = {0};
    aesni_encrypt(H, H, &ctx);
 
    // J0 = IV || 0x00000001
    uint8_t J0[16] = {0};
    memcpy(J0, iv, AES256GCM_IV_SIZE);
    J0[15] = 0x01;
 
    // CTR encryption starts at inc32(J0) = IV || 0x00000002
    uint8_t counter[16];
    memcpy(counter, J0, 16);
    gcm_incr32(counter);
 
    // Encrypt
    gcm_ctr(in, out, in_len, &ctx, counter);
 
    // Compute and write tag
    gcm_compute_tag(tag, H, J0, aad, aad_len, out, in_len, &ctx);
 
    // Zero all sensitive data
    secure_zero(H, 16);
    secure_zero(J0, 16);
    secure_zero(counter, 16);
    secure_zero(&ctx, sizeof(ctx));
 
    return 0;
}
 
 
int aes256gcm_decrypt(const uint8_t  *in, size_t in_len, const uint8_t  *aad, size_t aad_len,
                      const uint8_t key[AES256GCM_KEY_SIZE], const uint8_t iv[AES256GCM_IV_SIZE],
                      uint8_t tag[AES256GCM_TAG_SIZE], uint8_t *out){
    AESNI_Ctx ctx;
    aesni_init(key, AESNI_256, &ctx);
 
    uint8_t H[16] = {0};
    aesni_encrypt(H, H, &ctx);
 
    uint8_t J0[16] = {0};
    memcpy(J0, iv, AES256GCM_IV_SIZE);
    J0[15] = 0x01;
 
    // Compute tag from ciphertext before decrypting
    uint8_t expected_tag[16];
    gcm_compute_tag(expected_tag, H, J0, aad, aad_len, in, in_len, &ctx);
 
    // tag comparison
    int tag_mismatch = my_memcmp(expected_tag, tag, AES256GCM_TAG_SIZE);
    
    // tag matches
    if (!tag_mismatch){
        uint8_t counter[16];
        memcpy(counter, J0, 16);
        gcm_incr32(counter);
        gcm_ctr(in, out, in_len, &ctx, counter);
        secure_zero(counter, 16);
    }
    else{    // tag mismatch
        memset(out, 0, in_len);
    }
 
    secure_zero(H, 16);
    secure_zero(J0, 16);
    secure_zero(expected_tag, 16);
    secure_zero(&ctx, sizeof(ctx));
 
    return tag_mismatch ? -1 : 0;
}
 
