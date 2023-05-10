#ifndef vmessCrypto_h
#define vmessCrypto_h
#include <stdio.h>
#include "fnv.h"
#include "vmessTools.h"
static inline void toto_cryptor_type_info(toto_cryptor_type_t cipher,
                     size_t *key_len, size_t *iv_len,
                     size_t *tag_len)
{
    switch (cipher) {
    case AES_128_CFB:
        *key_len = AES_128_CFB_KEY_LEN;
        *iv_len = AES_128_CFB_IV_LEN;
        *tag_len = 0;
        break;
    case AEAD_AES_128_GCM:
        *key_len = AEAD_AES_128_GCM_KEY_LEN;
        *iv_len = AEAD_AES_128_GCM_IV_LEN;
        *tag_len = AEAD_AES_128_GCM_TAG_LEN;
        break;
    case AEAD_AES_256_GCM:
        *key_len = AEAD_AES_256_GCM_KEY_LEN;
        *iv_len = AEAD_AES_256_GCM_IV_LEN;
        *tag_len = AEAD_AES_256_GCM_TAG_LEN;
        break;
    case AEAD_CHACHA20_POLY1305:
        *key_len = AEAD_CHACHA20_POLY1305_KEY_LEN;
        *iv_len = AEAD_CHACHA20_POLY1305_IV_LEN;
        *tag_len = AEAD_CHACHA20_POLY1305_TAG_LEN;
        break;
    default:
        break;
    }
}
static int fnv1a(void *input, uint64_t input_len)
{
    return fnv_32a_buf(input, input_len, FNV1_32A_INIT);
}
static void hextobin(const char *str, uint8_t *bytes, size_t blen)
{
    uint8_t pos;
    uint8_t idx0;
    uint8_t idx1;
    const uint8_t hashmap[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
        0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 
    };
    memzero(bytes, blen);
    for (pos = 0; (pos < (blen * 2)); pos += 2) {
        idx0 = (uint8_t)str[pos + 0];
        idx1 = (uint8_t)str[pos + 1];
        bytes[pos / 2] = (uint8_t)(hashmap[idx0] << 4) | hashmap[idx1];
    };
}
static inline bool is_aead_cipher(toto_cryptor_type_t cipher)
{
    switch (cipher) {
    case AES_128_CFB:
        return false;
    case AEAD_AES_128_GCM:
    case AEAD_AES_256_GCM:
    case AEAD_CHACHA20_POLY1305:
    default:
        return true;
    }
}
static inline bool is_aead_cryptor(toto_cryptor_t *ptr)
{
    return is_aead_cipher(ptr->cipher);
}
void hl_hmac_md5(const uint8_t *key, int key_len, const uint8_t *data,
          uint64_t data_len, uint8_t *out, uint64_t *out_len);
int hl_rand_bytes(unsigned char *buf, int num);
void md5(const uint8_t *input, uint64_t input_len, uint8_t *res);
int aes_128_cfb_encrypt(const uint8_t *plaintext, int plaintext_len,
            const uint8_t *key, const uint8_t *iv,
                        uint8_t *ciphertext);
toto_cryptor_t *toto_cryptor_new(toto_cryptor_type_t cipher,
                   toto_cryptor_direction_t dir, const uint8_t *key,
                               const uint8_t *iv);
void toto_cryptor_free(toto_cryptor_t *ptr);
bool toto_cryptor_encrypt(toto_cryptor_t *ptr, const uint8_t *plaintext,
             size_t plaintext_len, uint8_t *tag,
             uint8_t *ciphertext, size_t *ciphertext_len);
bool toto_cryptor_decrypt(toto_cryptor_t *ptr, const uint8_t *ciphertext,
             size_t ciphertext_len, const uint8_t *tag,
                         uint8_t *plaintext, size_t *plaintext_len);
void toto_cryptor_reset_iv(toto_cryptor_t *ptr, const uint8_t *iv);
int aes_128_cfb_decrypt(const uint8_t *ciphertext, int ciphertext_len,
            const uint8_t *key, const uint8_t *iv,
            uint8_t *plaintext);
bool hkdf_sha1(const uint8_t *salt, size_t salt_len, const uint8_t *ikm,
           size_t ikm_len, const uint8_t *info, size_t info_len,
           uint8_t *okm, size_t okm_len);
static void evp_bytes_to_key(const uint8_t *input, size_t input_len,
                 uint8_t *key, size_t key_len)
{
    uint8_t round_res[16] = { 0 };
    size_t cur_pos = 0;
    uint8_t *buf = (uint8_t *)malloc(input_len + 16);
    memcpy(buf, input, input_len);
    while (cur_pos < key_len) {
        if (cur_pos == 0) {
            md5(buf, input_len, round_res);
        } else {
            memcpy(buf, round_res, 16);
            memcpy(buf + 16, input, input_len);
            md5(buf, input_len + 16, round_res);
        }
        for (int p = (int)cur_pos; p < key_len && p < cur_pos + 16; p++) {
            key[p] = round_res[p - cur_pos];
        }
        cur_pos += 16;
    }
    free(buf);
}
static void totovmess_increase_nonce(uint8_t *nonce, size_t bytes)
{
    uint16_t c = 1;
    for (size_t i = 0; i < bytes; ++i) {
        c += nonce[i];
        nonce[i] = c & 0xff;
        c >>= 8;
    }
}
#endif 
