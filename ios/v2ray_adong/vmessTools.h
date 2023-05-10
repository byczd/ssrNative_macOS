#ifndef vmessTools_h
#define vmessTools_h
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#define TOTOVE_DEFAULT_BUFSIZE 2048 
#define BUFSIZE_512 512
#define BUFSIZE_16K 16 * 1024  
#define memzero(buf, n) (void)memset(buf, 0, n)
#define SHA224_LEN 28
#define MD5_LEN 16
#define AES_128_CFB_KEY_LEN 16
#define AES_128_CFB_IV_LEN 16
#define AEAD_AES_128_GCM_KEY_LEN 16
#define AEAD_AES_128_GCM_IV_LEN 12
#define AEAD_AES_128_GCM_TAG_LEN 16
#define AEAD_AES_256_GCM_KEY_LEN 32
#define AEAD_AES_256_GCM_IV_LEN 12
#define AEAD_AES_256_GCM_TAG_LEN 16
#define AEAD_CHACHA20_POLY1305_KEY_LEN 32
#define AEAD_CHACHA20_POLY1305_IV_LEN 12
#define AEAD_CHACHA20_POLY1305_TAG_LEN 16
typedef struct toto_buffer_s {
    uint8_t *buffer;
    size_t cap;
} toto_buffer_t;
static inline int toto_get_addr_len(const uint8_t *data)
{
    switch (data[0] ) {
    case 0x01:
        return 4;
    case 0x03:
        return 1 + data[1];
    case 0x04:
        return 16;
    default:
        break;
    }
    return 0;
}
typedef struct toto_ssl_ctx_s {
    SSL_CTX *_;
}toto_ssl_ctx_t;
typedef struct toto_server_config_s {
    const char *server_address;
    const char *server_type;
    int server_port;
    uint8_t *password;
    void *extra; 
} toto_server_config_t;
typedef struct toto_session_outbound_s {
    bool ready;
    const toto_server_config_t *server_config;
    char *dest;
    int port;
    void *ctx;  
    struct tunnel_ctx *tunnel; 
    void (*outbound_socket_ctx_write_fn)(struct toto_session_outbound_s* outbound, const void* data, size_t len,bool is2Local); 
    toto_ssl_ctx_t *ssl_ctx; 
}toto_session_outbound_t;
typedef enum { TOTOVE_ENCRYPT, TOTOVE_DECRYPT } toto_cryptor_direction_t;
typedef enum {
    AES_128_CFB = 0x00, 
    AEAD_AES_128_GCM = 0x03, 
    AEAD_CHACHA20_POLY1305 = 0x04, 
    AEAD_AES_256_GCM = 0x05, 
} toto_cryptor_type_t;
typedef struct toto_cryptor_s {
    toto_cryptor_type_t cipher;
    toto_cryptor_direction_t dir;
    const uint8_t *key;
    const uint8_t *iv;
    size_t key_len;
    size_t iv_len;
    size_t tag_len;
    void *ctx;
} toto_cryptor_t;
typedef struct toto_outbound_ctx_v2ray_s {
    uint8_t iv[AES_128_CFB_IV_LEN];
    uint8_t key[AES_128_CFB_KEY_LEN];
    uint8_t riv[AES_128_CFB_IV_LEN];
    uint8_t rkey[AES_128_CFB_KEY_LEN];
    toto_buffer_t *lrbuf; 
    toto_buffer_t *lwbuf; 
    toto_buffer_t *rrbuf; 
    toto_buffer_t *rwbuf; 
    uint8_t target_addr[BUFSIZE_512]; 
    const uint8_t *cmd; 
    size_t cmdlen;
    bool header_sent; 
    uint8_t v;
    bool header_recved;
    size_t resp_len;
    size_t target_addr_len;
    size_t remote_rbuf_pos;
    uint32_t resp_hash;
    uint8_t *data_enc_iv;
    uint8_t *data_enc_key;
    uint8_t *data_dec_iv;
    uint8_t *data_dec_key;
    size_t key_len;
    size_t iv_len;
    size_t tag_len;
    uint16_t enc_counter;
    uint16_t dec_counter;
    toto_cryptor_t *encryptor;
    toto_cryptor_t *decryptor;
    toto_cryptor_type_t cipher;
} toto_outbound_ctx_v2ray_t;
typedef struct toto_outbound_ctx_ss_s {
    toto_buffer_t *rbuf;
    toto_buffer_t *wbuf;
    const uint8_t *cmd;
    size_t cmd_len;
    bool iv_sent;
    enum {
        READY = 0,
        WAIT_MORE_FOR_LEN, 
        WAIT_MORE_FOR_PAYLOAD, 
    } aead_decode_state;
    size_t plen;
    uint8_t *enc_key; 
    uint8_t *enc_iv;
    uint8_t *dec_key; 
    uint8_t *dec_iv; 
    uint8_t *ikm;
    uint8_t *enc_salt;
    size_t key_len;
    size_t iv_len;
    size_t tag_len;
    toto_cryptor_t *encryptor;
    toto_cryptor_t *decryptor;
    toto_cryptor_type_t cipher;
} toto_outbound_ctx_ss_t;
typedef struct toto_config_ssl_s {
    bool enabled;
    const char *sni;
    const char *ssl_crt;
    bool ssl_verify;
} toto_config_ssl_t;
typedef struct toto_config_ws_s {
    bool enabled;
    const char *path;
    const char *hostname;
} toto_config_ws_t;
typedef struct toto_config_extra_v2ray_s {
    toto_config_ws_t websocket;
    toto_config_ssl_t ssl;
    toto_cryptor_type_t secure;
} toto_config_extra_v2ray_t;
typedef struct toto_config_extra_ss_s {
    toto_cryptor_type_t method;
    const char *obfs;
    const char *obfs_host;
    const char *ssl_crt;
    bool ssl_verify;
} toto_config_extra_ss_t;
typedef struct toto_ws_resp_s {
    int fin;
    int opcode;
    int mask;
    uint64_t payload_len; 
    size_t header_len;
} toto_ws_resp_t;
typedef struct toto_vmess_resp_s {
    uint8_t v;
    uint8_t opt;
    uint8_t cmd;
    uint8_t m;
} toto_vmess_resp_t;
toto_buffer_t *toto_buffer_new(void);
toto_buffer_t *toto_buffer_new_size(size_t size);
void toto_buffer_free(toto_buffer_t *);
void toto_buffer_ensure(toto_buffer_t *, size_t);
#endif 
