#include "vmessPro.h"
#include "time.h"
const char vmess_key_suffix[36] = "c48619fe-8f02-49e0-b9e9-edf763e17e21";
static void hl_vmess_init_encryptor(toto_outbound_ctx_v2ray_t *ctx);
static void hl_vmess_init_decryptor(toto_outbound_ctx_v2ray_t *ctx);
static void totovmess_vmess_increase_cryptor_iv(toto_outbound_ctx_v2ray_t *ctx, toto_cryptor_direction_t dir);
static size_t hl_vmess_write_head(uint8_t *uuid,bool is_udp, toto_outbound_ctx_v2ray_t *ctx);
static size_t hl_vmess_write_body(const uint8_t *data,size_t data_len, size_t head_len,toto_session_outbound_t *outbound);
static bool vmess_write_local_cfb(toto_session_outbound_t *outbound, const uint8_t *data,size_t data_len, size_t *olen);
static bool vmess_write_local_aead(toto_session_outbound_t *outbound, const uint8_t *data,size_t data_len, size_t *olen);
static void hl_outbound_ctx_v2ray_free(toto_outbound_ctx_v2ray_t *ptr);
static toto_config_extra_v2ray_t *hl_config_extra_v2ray_parse(const char *secure,const char *sni,const char *ws_path,const char *ws_hostname);
static toto_config_extra_v2ray_t *toto_config_extra_v2ray_new(void);
static void hl_outbound_ctx_ss_free(toto_outbound_ctx_ss_t *ptr);
static toto_config_extra_ss_t *hl_config_extra_ss_parse(const char *method,const char *obfs,const char *obfs_host,bool sslVerify,const char *certfile);
static void totovmess_ss_increase_cryptor_iv(toto_outbound_ctx_ss_t *ctx,toto_cryptor_direction_t dir);
static bool hl_encrypt_shadowsocks_data(toto_session_outbound_t *outbound, const uint8_t *msg, size_t len,  size_t *olen);
static bool hl_decrypt_shadowsocks_data(toto_session_outbound_t *outbound, const uint8_t *msg, size_t len, size_t *olen, size_t *clen);
static toto_config_extra_ss_t *toto_config_extra_ss_new(void);
#pragma clang diagnostic ignored"-Wshorten-64-to-32"
toto_session_outbound_t *hl_session_outbound_new(void)
{
    toto_session_outbound_t *ptr = malloc(sizeof(toto_session_outbound_t));
    ptr->ready = false; 
    ptr->dest = NULL;
    ptr->port = 0;
    ptr->server_config = NULL;
    ptr->ctx = NULL;
    ptr->tunnel = NULL;
    ptr->outbound_socket_ctx_write_fn=NULL;
    return ptr;
}
void hl_session_outbound_free(toto_session_outbound_t *ptr)
{
    if (ptr->ctx) {
        if (strcasecmp(ptr->server_config->server_type, "shadowsocks") == 0) {
            hl_outbound_ctx_ss_free((toto_outbound_ctx_ss_t *)ptr->ctx);
        }
        else if (strcasecmp(ptr->server_config->server_type, "vmess") == 0){
            hl_outbound_ctx_v2ray_free((toto_outbound_ctx_v2ray_t *)ptr->ctx);
        }
    }
    if (ptr->dest)
        free(ptr->dest);
    ptr->ctx = NULL;
    ptr->dest = NULL;
    free(ptr);
    ptr = NULL;
}
toto_outbound_ctx_v2ray_t *hl_outbound_ctx_v2ray_new(const uint8_t *cmd,
                             size_t cmdlen,
                             toto_cryptor_type_t cipher)
{
    toto_outbound_ctx_v2ray_t *ptr = (toto_outbound_ctx_v2ray_t *)calloc(1, sizeof(toto_outbound_ctx_v2ray_t));
    toto_cryptor_type_info(cipher, &ptr->key_len, &ptr->iv_len, &ptr->tag_len);
    ptr->data_enc_key = calloc(1, ptr->key_len);
    ptr->data_enc_iv = calloc(1, ptr->iv_len);
    ptr->data_dec_key = calloc(1, ptr->key_len);
    ptr->data_dec_iv = calloc(1, ptr->iv_len);
    ptr->enc_counter = 0;
    ptr->dec_counter = 0;
    ptr->cmd = calloc(cmdlen, sizeof(uint8_t));
    memcpy((void *)ptr->cmd, cmd, cmdlen);
    ptr->cmdlen = cmdlen;
    ptr->cipher = cipher;
    ptr->header_sent=false;
    ptr->header_recved=false;
    ptr->lrbuf = toto_buffer_new();
    ptr->lwbuf = toto_buffer_new();
    ptr->rrbuf = toto_buffer_new();
    ptr->rwbuf = toto_buffer_new();
    return ptr;
}
static void hl_outbound_ctx_v2ray_free(toto_outbound_ctx_v2ray_t *ptr)
{
    if (ptr->encryptor)
        toto_cryptor_free(ptr->encryptor);
    if (ptr->decryptor)
        toto_cryptor_free(ptr->decryptor);
    if (ptr->data_enc_iv)
        free(ptr->data_enc_iv);
    if (ptr->data_enc_key)
        free(ptr->data_enc_key);
    if (ptr->data_dec_iv)
        free(ptr->data_dec_iv);
    if (ptr->data_dec_key)
        free(ptr->data_dec_key);
    if (ptr->lrbuf)
        toto_buffer_free(ptr->lrbuf);
    if (ptr->lwbuf)
        toto_buffer_free(ptr->lwbuf);
    if (ptr->rrbuf)
        toto_buffer_free(ptr->rrbuf);
    if (ptr->rwbuf)
        toto_buffer_free(ptr->rwbuf);
    if (ptr->cmd) {
        free((void *)ptr->cmd);
        ptr->cmd=NULL;
    }
    ptr->encryptor = NULL;
    ptr->decryptor = NULL;
    ptr->data_enc_iv = NULL;
    ptr->data_enc_key = NULL;
    ptr->data_dec_iv = NULL;
    ptr->data_dec_key = NULL;
    if (ptr)
        free(ptr);
    ptr = NULL;
}
static void totovmess_vmess_increase_cryptor_iv(toto_outbound_ctx_v2ray_t *ctx,
                      toto_cryptor_direction_t dir)
{
    if (ctx->cipher == AES_128_CFB)
        return;
    uint16_t *counter = NULL;
    toto_cryptor_t *cryptor = NULL;
    uint8_t *iv = NULL;
    switch (dir) {
    case TOTOVE_DECRYPT:
        counter = &ctx->dec_counter;
        cryptor = ctx->decryptor;
        iv = ctx->data_dec_iv;
        break;
    case TOTOVE_ENCRYPT:
        counter = &ctx->enc_counter;
        cryptor = ctx->encryptor;
        iv = ctx->data_enc_iv;
        break;
    default:
        break;
    }
    if (counter != NULL && cryptor != NULL) {
        *counter += 1;
        iv[0] = *counter >> 8;
        iv[1] = *counter;
        toto_cryptor_reset_iv(cryptor, iv);
    }
}
bool hl_vmess_write_data_2_remote(toto_session_outbound_t *outbound,const uint8_t *data, size_t data_len){
    size_t head_len = 0;
    toto_outbound_ctx_v2ray_t *ctx=(toto_outbound_ctx_v2ray_t *)outbound->ctx;
    if (!ctx->header_sent) {
        uint8_t *uuid=outbound->server_config->password;
        head_len = hl_vmess_write_head(uuid,false,ctx);
        ctx->header_sent=true;
    }
    hl_vmess_write_body(data, data_len, head_len,outbound);
    return true;
}
static size_t hl_vmess_write_head(uint8_t *uuid,bool is_udp, toto_outbound_ctx_v2ray_t *ctx)
{
    const uint8_t *udp_rbuf = NULL;
    uint8_t *rwbuf;
    const uint8_t *socks5_cmd = ctx->cmd;
    size_t socks5_cmd_len = ctx->cmdlen;
    time_t now = time(NULL);
    unsigned long ts = htonll(now);
    uint8_t header_auth[MD5_LEN];
    uint64_t header_auth_len = 0; 
    hl_hmac_md5(uuid, 16, (const uint8_t *)&ts, 8, header_auth, &header_auth_len);
    assert(header_auth_len == MD5_LEN);
    toto_buffer_ensure(ctx->rwbuf, header_auth_len);
    rwbuf = ctx->rwbuf->buffer;  
    memcpy(rwbuf, header_auth, header_auth_len);
    int n = socks5_cmd_len - 4 - 2;  
    if (is_udp) {
        n = toto_get_addr_len(udp_rbuf + 3);
    }
    int p = 0;
    size_t header_cmd_len =
        1 + 16 + 16 + 1 + 1 + 1 + 1 + 1 + 2 + 1 + n + p + 4;
    uint8_t header_cmd_raw[header_cmd_len];
    uint8_t header_cmd_encoded[header_cmd_len];
    memzero(header_cmd_raw, header_cmd_len);
    memzero(header_cmd_encoded, header_cmd_len);
    int offset = 0;
    header_cmd_raw[0] = 1; 
    offset += 1;
    hl_rand_bytes(header_cmd_raw + offset, AES_128_CFB_IV_LEN); 
    memcpy(ctx->iv, header_cmd_raw + offset, AES_128_CFB_IV_LEN);
    offset += AES_128_CFB_IV_LEN;
    hl_rand_bytes(header_cmd_raw + offset, AES_128_CFB_KEY_LEN); 
    memcpy(ctx->key, header_cmd_raw + offset, AES_128_CFB_KEY_LEN);
    offset += AES_128_CFB_KEY_LEN;
    if (!ctx->encryptor)
        hl_vmess_init_encryptor(ctx);
    assert(ctx->encryptor != NULL);
    if (!ctx->decryptor)
        hl_vmess_init_decryptor(ctx);
    assert(ctx->decryptor != NULL);
    hl_rand_bytes(header_cmd_raw + offset, 1); 
    ctx->v = header_cmd_raw[offset];
    offset += 1;
    header_cmd_raw[offset] = 0x01; 
    offset += 1;
    header_cmd_raw[offset] = ctx->cipher; 
    offset += 1;
    header_cmd_raw[offset] = 0x00; 
    offset += 1;
    if (is_udp) {
        header_cmd_raw[offset] = 0x02;
    } else {
        header_cmd_raw[offset] = 0x01;  
    }
    offset += 1;
    if (is_udp) {
        header_cmd_raw[offset] = udp_rbuf[4 + n];
        header_cmd_raw[offset + 1] = udp_rbuf[4 + n + 1];
        offset += 2;
        if (udp_rbuf[3] == 0x01) {
            header_cmd_raw[offset] = 0x01;
        } else {
            header_cmd_raw[offset] = udp_rbuf[3] - 1;
        }
        offset += 1;
        memcpy(header_cmd_raw + offset, udp_rbuf + 4, n);
        offset += n;
    } else {
        header_cmd_raw[offset] = socks5_cmd[socks5_cmd_len - 2];
        header_cmd_raw[offset + 1] = socks5_cmd[socks5_cmd_len - 1];
        offset += 2;
        if (socks5_cmd[3] == 0x01) {
            header_cmd_raw[offset] = 0x01;  
        } else {
            header_cmd_raw[offset] = socks5_cmd[3] - 1; 
        }
        offset += 1;
        memcpy(header_cmd_raw + offset, socks5_cmd + 4, n);
        offset += n;
    }
    assert(offset + 4 == header_cmd_len);
    unsigned int f = fnv1a(header_cmd_raw, header_cmd_len - 4);
    header_cmd_raw[offset] = f >> 24;
    header_cmd_raw[offset + 1] = f >> 16;
    header_cmd_raw[offset + 2] = f >> 8;
    header_cmd_raw[offset + 3] = f;
    uint8_t k_md5_input[16 + 36];
    memcpy(k_md5_input, uuid, 16);
    memcpy(k_md5_input + 16, vmess_key_suffix, 36);
    uint8_t cmd_k[AES_128_CFB_KEY_LEN];
    md5(k_md5_input, 16 + 36, cmd_k); 
    uint8_t iv_md5_input[32];
    now = time(NULL);
    ts = htonll(now);
    memcpy(iv_md5_input, (const unsigned char *)&ts, 8);
    memcpy(iv_md5_input + 8, (const unsigned char *)&ts, 8);
    memcpy(iv_md5_input + 16, (const unsigned char *)&ts, 8);
    memcpy(iv_md5_input + 24, (const unsigned char *)&ts, 8);
    uint8_t cmd_iv[AES_128_CFB_IV_LEN];
    md5(iv_md5_input, 32, cmd_iv); 
    aes_128_cfb_encrypt(header_cmd_raw, header_cmd_len, cmd_k, cmd_iv, header_cmd_encoded);
    toto_buffer_ensure(ctx->rwbuf, header_auth_len + header_cmd_len);
    rwbuf = ctx->rwbuf->buffer; 
    memcpy(rwbuf + header_auth_len, header_cmd_encoded, header_cmd_len);
    return header_auth_len + header_cmd_len;
}
static size_t hl_vmess_write_body(const uint8_t *data,size_t data_len, size_t head_len,toto_session_outbound_t *outbound)
{
    uint8_t *rwbuf, *lrbuf;
    size_t sent = 0, offset = 0, remains = data_len,
           frame_data_len = data_len;
    toto_outbound_ctx_v2ray_t *ctx=(toto_outbound_ctx_v2ray_t *)outbound->ctx;
    while (remains > 0) {
        switch (ctx->cipher) {
        case AES_128_CFB: {
            if (remains + 6 > BUFSIZE_16K - head_len) { 
                frame_data_len = BUFSIZE_16K - head_len - 6; 
            } else {
                frame_data_len = remains;
            }
            toto_buffer_ensure(ctx->lrbuf, frame_data_len + 6); 
            lrbuf = ctx->lrbuf->buffer;
            toto_buffer_ensure(ctx->rwbuf,
                      head_len + frame_data_len + 6);
            rwbuf = ctx->rwbuf->buffer;
            lrbuf[0] = (frame_data_len + 4) >> 8;
            lrbuf[1] = (frame_data_len + 4);
            unsigned int f =fnv1a((void *)data + offset, frame_data_len);
            lrbuf[2] = f >> 24;
            lrbuf[3] = f >> 16;
            lrbuf[4] = f >> 8;
            lrbuf[5] = f;
            memcpy(lrbuf + 6, data + offset, frame_data_len); 
            size_t ciphertext_len = 0;
            toto_cryptor_encrypt(ctx->encryptor, lrbuf,
                        frame_data_len + 6, NULL,
                        rwbuf + head_len, &ciphertext_len);
            sent += (frame_data_len + 6);
            if (outbound->outbound_socket_ctx_write_fn) {
                outbound->outbound_socket_ctx_write_fn(outbound,rwbuf,head_len + frame_data_len + 6,false);
            }
            break;
        }
        case AEAD_AES_128_GCM:
        case AEAD_CHACHA20_POLY1305: {
            if (remains + 18 > BUFSIZE_16K - head_len) { 
                frame_data_len = BUFSIZE_16K - head_len - 18;
            } else {
                frame_data_len = remains;
            }
            toto_buffer_ensure(ctx->rwbuf,
                      head_len + frame_data_len + 18);
            rwbuf = ctx->rwbuf->buffer;
            rwbuf[head_len + 0] = (frame_data_len + 16) >> 8;
            rwbuf[head_len + 1] = (frame_data_len + 16);
            size_t ciphertext_len = 0;
            bool ok = toto_cryptor_encrypt(
                ctx->encryptor, data + offset, frame_data_len,
                rwbuf + head_len + 2 + frame_data_len,
                rwbuf + head_len + 2, &ciphertext_len);
            totovmess_vmess_increase_cryptor_iv(ctx, TOTOVE_ENCRYPT); 
            if (!ok) {
                printf("toto_cryptor_encrypt:failed\n");
            }
            assert(ciphertext_len == frame_data_len);
            sent += (frame_data_len + 18);
            if (outbound->outbound_socket_ctx_write_fn) {
                outbound->outbound_socket_ctx_write_fn(outbound,rwbuf,head_len + frame_data_len + 18,false);
            }
            break;
        }
        default:
            break;
        }
        offset += frame_data_len;
        remains -= frame_data_len;
        if (head_len > 0)
            head_len = 0;
    }
    return sent;
}
static bool vmess_write_local_cfb(toto_session_outbound_t *outbound, const uint8_t *data,
                  size_t data_len, size_t *olen)
{
    toto_outbound_ctx_v2ray_t *ctx = outbound->ctx;
    toto_vmess_resp_t meta = { 0 };
    uint8_t *rrbuf = ctx->rrbuf->buffer, *lwbuf = ctx->lwbuf->buffer;
    toto_cryptor_t *decryptor = ctx->decryptor;
    size_t decrypt_len = 0;
    if (!ctx->header_recved) {
        if (data_len < 4)
            return false;
        if (!toto_cryptor_decrypt(decryptor, data, 4, NULL, rrbuf,
                     &decrypt_len))
            return false;
        meta.v = rrbuf[0];
        meta.opt = rrbuf[1];
        meta.cmd = rrbuf[2];
        meta.m = rrbuf[3];
        if (meta.v != ctx->v)
            return false;
        if (meta.m != 0) 
            return false;
        ctx->header_recved = true;
        ctx->resp_len = 0;
        return vmess_write_local_cfb(outbound, data + 4, data_len - 4,
                         olen);
    }
    if (ctx->resp_len == 0) {
        if (data_len == 0) 
            return true;
        if (data_len < 2) 
            return false;
        if (!toto_cryptor_decrypt(decryptor, data, 2, NULL, rrbuf,
                     &decrypt_len))
            return false;
        int l = rrbuf[0] << 8 | rrbuf[1];
        if (l == 0 || l == 4) 
            return true;
        if (l < 4)
            return false;
        ctx->resp_len = l - 4;
        ctx->resp_hash = 0;
        return vmess_write_local_cfb(outbound, data + 2, data_len - 2,
                         olen);
    }
    if (ctx->resp_hash == 0) {
        if (data_len < 4) 
            return false;
        if (!toto_cryptor_decrypt(decryptor, data, 4, NULL, rrbuf,
                     &decrypt_len))
            return false;
        ctx->resp_hash = (uint32_t)rrbuf[0] << 24 | rrbuf[1] << 16 |
                 rrbuf[2] << 8 | rrbuf[3];
        return vmess_write_local_cfb(outbound, data + 4, data_len - 4,
                         olen);
    }
    if (data_len <= 0) 
        return true;
    size_t data_to_decrypt =
        ctx->resp_len < data_len ? ctx->resp_len : data_len;
    toto_buffer_ensure(ctx->lwbuf, data_to_decrypt);
    lwbuf = ctx->lwbuf->buffer;
    if (!toto_cryptor_decrypt(decryptor, data, data_to_decrypt, NULL, lwbuf,
                 &decrypt_len))
        return false;
    if (outbound->outbound_socket_ctx_write_fn) {
        outbound->outbound_socket_ctx_write_fn(outbound,lwbuf,data_to_decrypt,true);
    }
    *olen += data_len;
    ctx->resp_len -= data_to_decrypt;
    return vmess_write_local_cfb(outbound, data + data_to_decrypt,
                     data_len - data_to_decrypt, olen);
}
static bool vmess_write_local_aead(toto_session_outbound_t *outbound, const uint8_t *data,
                   size_t data_len, size_t *olen)
{
    toto_outbound_ctx_v2ray_t *ctx = outbound->ctx;
    toto_vmess_resp_t meta = { 0 };
    uint8_t *rrbuf = ctx->rrbuf->buffer;
    uint8_t *lwbuf = ctx->lwbuf->buffer;
    toto_cryptor_t *decryptor = ctx->decryptor;
    if (!ctx->header_recved) {
        if (data_len < 4)
            return false;
        if (!aes_128_cfb_decrypt(data, 4, (const uint8_t *)ctx->rkey,
                     (const uint8_t *)ctx->riv, rrbuf))
            return false;
        meta.v = rrbuf[0];
        meta.opt = rrbuf[1];
        meta.cmd = rrbuf[2];
        meta.m = rrbuf[3];
        if (meta.v != ctx->v)
            return false;  
        if (meta.m != 0) 
            return false;
        ctx->header_recved = true;
        ctx->resp_len = 0;
        return vmess_write_local_aead(outbound, data + 4, data_len - 4,
                          olen);
    }
    if (ctx->resp_len == 0) {
        if (data_len == 0) 
            return true;
        if (data_len < 2) 
            return false;
        int l = data[0] << 8 | data[1];
        if (l == 0 || l == 16) 
            return true;
        if (l < 16)
            return false;
        ctx->resp_len = l - 16;
        ctx->resp_hash = -1;
        return vmess_write_local_aead(outbound, data + 2, data_len - 2,
                          olen);
    }
    if (ctx->remote_rbuf_pos + data_len < ctx->resp_len + 16) {
        toto_buffer_ensure(ctx->rrbuf, ctx->remote_rbuf_pos + data_len);
        rrbuf = ctx->rrbuf->buffer;
        memcpy(rrbuf + ctx->remote_rbuf_pos, data, data_len);
        ctx->remote_rbuf_pos += data_len;
        return true;
    }
    size_t decrypt_len = 0;
    if (ctx->remote_rbuf_pos == 0) {
        size_t data_to_decrypt = ctx->resp_len;
        toto_buffer_ensure(ctx->lwbuf, data_to_decrypt);
        lwbuf = ctx->lwbuf->buffer;
        bool ok = toto_cryptor_decrypt(decryptor, data, ctx->resp_len,
                          data + ctx->resp_len, lwbuf,
                          &decrypt_len);
        totovmess_vmess_increase_cryptor_iv(ctx, TOTOVE_DECRYPT);
        if (!ok)
            return false;
        if (outbound->outbound_socket_ctx_write_fn && lwbuf && data_to_decrypt>0) {
            outbound->outbound_socket_ctx_write_fn(outbound,lwbuf,data_to_decrypt,true);
        }
        *olen += data_to_decrypt;
        ctx->resp_len -= data_to_decrypt;
        return vmess_write_local_aead(outbound,
                          data + data_to_decrypt + 16,
                          data_len - data_to_decrypt - 16,
                          olen);
    } else {
        size_t data_to_read = ctx->resp_len + 16 - ctx->remote_rbuf_pos;
        toto_buffer_ensure(ctx->rrbuf,
                  ctx->remote_rbuf_pos + data_to_read);
        rrbuf = ctx->rrbuf->buffer;
        memcpy(rrbuf + ctx->remote_rbuf_pos, data, data_to_read);
        toto_buffer_ensure(ctx->lwbuf, ctx->resp_len);
        lwbuf = ctx->lwbuf->buffer;
        bool ok = toto_cryptor_decrypt(decryptor, rrbuf, ctx->resp_len,
                          rrbuf + ctx->resp_len, lwbuf,
                          &decrypt_len);
        totovmess_vmess_increase_cryptor_iv(ctx, TOTOVE_DECRYPT);
        if (!ok)
            return false;
        if (outbound->outbound_socket_ctx_write_fn) {
            outbound->outbound_socket_ctx_write_fn(outbound,lwbuf,ctx->resp_len,true);
        }
        *olen += ctx->resp_len;
        ctx->resp_len = 0;
        ctx->remote_rbuf_pos = 0;
        return vmess_write_local_aead(outbound, data + data_to_read,
                          data_len - data_to_read, olen);
    }
}
bool hl_vmess_write_data_2_local(toto_session_outbound_t *outbound, const uint8_t *data,
               size_t data_len, size_t *olen)
{
    toto_outbound_ctx_v2ray_t *ctx = outbound->ctx;
    switch (ctx->cipher) {
    case AES_128_CFB:
        return vmess_write_local_cfb(outbound, data, data_len, olen);
    case AEAD_AES_128_GCM:
    case AEAD_CHACHA20_POLY1305:
        return vmess_write_local_aead(outbound, data, data_len, olen);
    default:
        break;
    }
    return false;
}
uint8_t * hl_decode_vemss_data(toto_session_outbound_t *outbound, const uint8_t *data,
                               size_t data_len, size_t *olen){
    if (hl_vmess_write_data_2_local(outbound,data,data_len,olen)) {
        toto_outbound_ctx_v2ray_t *ctx = outbound->ctx;
        return ctx->lwbuf->buffer;
    }
    else
        return NULL;
}
static void hl_vmess_init_encryptor(toto_outbound_ctx_v2ray_t *ctx)
{
    switch (ctx->cipher) {
    case AES_128_CFB:
        ctx->encryptor = toto_cryptor_new(ctx->cipher, TOTOVE_ENCRYPT,
                         (const uint8_t *)ctx->key,
                         (const uint8_t *)ctx->iv);
        break;
    case AEAD_AES_128_GCM:
        assert(ctx->iv_len == AEAD_AES_128_GCM_IV_LEN);
        assert(ctx->key_len == AEAD_AES_128_GCM_KEY_LEN);
        memcpy(ctx->data_enc_key, ctx->key, AEAD_AES_128_GCM_KEY_LEN);
        memcpy(ctx->data_enc_iv + 2, ctx->iv + 2, 10);
        ctx->encryptor =
            toto_cryptor_new(ctx->cipher, TOTOVE_ENCRYPT,
                    (const uint8_t *)ctx->data_enc_key,
                    (const uint8_t *)ctx->data_enc_iv);
        break;
    case AEAD_CHACHA20_POLY1305:
        assert(ctx->iv_len == AEAD_CHACHA20_POLY1305_IV_LEN);
        assert(ctx->key_len == AEAD_CHACHA20_POLY1305_KEY_LEN);
        md5((const uint8_t *)ctx->key, AES_128_CFB_IV_LEN,
            ctx->data_enc_key);
        md5(ctx->data_enc_key, MD5_LEN, ctx->data_enc_key + MD5_LEN);
        memcpy(ctx->data_enc_iv + 2, ctx->iv + 2, 10);
        ctx->encryptor =
            toto_cryptor_new(ctx->cipher, TOTOVE_ENCRYPT,
                    (const uint8_t *)ctx->data_enc_key,
                    (const uint8_t *)ctx->data_enc_iv);
        break;
    case AEAD_AES_256_GCM:
    default:
        break;
    }
}
static void hl_vmess_init_decryptor(toto_outbound_ctx_v2ray_t *ctx)
{
    md5((const uint8_t *)ctx->iv, AES_128_CFB_IV_LEN, (uint8_t *)ctx->riv);
    md5((const uint8_t *)ctx->key, AES_128_CFB_KEY_LEN,
        (uint8_t *)ctx->rkey);
    switch (ctx->cipher) {
    case AES_128_CFB:
        ctx->decryptor = toto_cryptor_new(ctx->cipher, TOTOVE_DECRYPT,
                         (const uint8_t *)ctx->rkey,
                         (const uint8_t *)ctx->riv);
        break;
    case AEAD_AES_128_GCM:
        assert(ctx->iv_len == AEAD_AES_128_GCM_IV_LEN);
        assert(ctx->key_len == AEAD_AES_128_GCM_KEY_LEN);
        memcpy(ctx->data_dec_key, ctx->rkey, AEAD_AES_128_GCM_KEY_LEN);
        ctx->dec_counter = 0;
        memcpy(ctx->data_dec_iv + 2, ctx->riv + 2, 10);
        ctx->decryptor =
            toto_cryptor_new(ctx->cipher, TOTOVE_DECRYPT,
                    (const uint8_t *)ctx->data_dec_key,
                    (const uint8_t *)ctx->data_dec_iv);
        break;
    case AEAD_CHACHA20_POLY1305:
        assert(ctx->iv_len == AEAD_CHACHA20_POLY1305_IV_LEN);
        assert(ctx->key_len == AEAD_CHACHA20_POLY1305_KEY_LEN);
        md5((const uint8_t *)ctx->rkey, AES_128_CFB_IV_LEN,
            ctx->data_dec_key);
        md5(ctx->data_dec_key, MD5_LEN, ctx->data_dec_key + MD5_LEN);
        ctx->dec_counter = 0;
        memcpy(ctx->data_dec_iv + 2, ctx->riv + 2, 10);
        ctx->decryptor =
            toto_cryptor_new(ctx->cipher, TOTOVE_DECRYPT,
                    (const uint8_t *)ctx->data_dec_key,
                    (const uint8_t *)ctx->data_dec_iv);
        break;
    case AEAD_AES_256_GCM:
    default:
        break;
    }
}
static toto_config_extra_v2ray_t *toto_config_extra_v2ray_new(void)
{
    toto_config_extra_v2ray_t *ptr =malloc(sizeof(toto_config_extra_v2ray_t));
    ptr->ssl.enabled = false;
    ptr->ssl.sni = NULL;
    ptr->websocket.enabled = false;
    ptr->websocket.hostname = NULL;
    ptr->websocket.path = NULL;
    ptr->secure = AES_128_CFB;
    return ptr;
}
void toto_config_extra_v2ray_free(toto_config_extra_v2ray_t *ptr)
{
    free(ptr);
    ptr = NULL;
}
static toto_config_extra_v2ray_t *hl_config_extra_v2ray_parse(const char *secure,const char *sni,const char *ws_path,const char *ws_hostname)
{
    toto_config_extra_v2ray_t *ptr = toto_config_extra_v2ray_new();
    if (secure != NULL) {
        if (strcasecmp(secure, "aes-128-gcm") == 0) {
            ptr->secure = AEAD_AES_128_GCM;
        }
        else if (strcasecmp(secure, "aes-256-gcm") == 0) {
            ptr->secure = AEAD_AES_256_GCM;
        }
        else if (strcasecmp(secure, "aes-128-cfb") == 0) {
            ptr->secure = AES_128_CFB;
        } else if (strcasecmp(secure, "chacha20-ietf-poly1305") == 0) {
            ptr->secure = AEAD_CHACHA20_POLY1305;
        }
    }
    else
        goto error;
    ptr->ssl.enabled=false;
    if (sni!=NULL) {
        ptr->ssl.enabled=true;
        ptr->ssl.sni = sni;
    }
    if (ws_path != NULL) {
        ptr->websocket.enabled = true;
        ptr->websocket.path = ws_path;
    }
    if (ws_hostname != NULL){
        ptr->websocket.enabled = true;
        ptr->websocket.hostname = ws_hostname;
    }
    return ptr;
error:
    toto_config_extra_v2ray_free(ptr);
    return NULL;
}
toto_server_config_t *hl_config_parse_servers(struct server_config* config)
{
    toto_server_config_t *ptr = malloc(sizeof(toto_server_config_t));
    ptr->server_address=config->remote_host;
    ptr->server_port=config->remote_port;
    ptr->server_type=config->proxytype;
    if (strcasecmp(config->proxytype, "ss") == 0 ) {
        ptr->server_type = "shadowsocks";
    }
    if (strcasecmp(ptr->server_type, "shadowsocks") == 0) {
        uint8_t *pass = (uint8_t *)strdup(config->password); 
         ptr->password = pass;
    }
    else if (strcasecmp(ptr->server_type, "vmess") == 0) {
        size_t len = strlen(config->password);
        if (len != 36) 
            goto error;
        char uuid_hex[32];
        for (int j = 0, k = 0; j < 36 && k < 32;) {
            if (config->password[j] != '-')
                uuid_hex[k++] = config->password[j++];
            else
                j++;
        }
        uint8_t *uuid = malloc(16 * sizeof(uint8_t));
        hextobin(uuid_hex, uuid, 16);
        ptr->password = uuid;
    }
    char *sni=NULL;
    if (config->over_tls_enable) {
        sni="";
    }
    ptr->extra = NULL;
    if (strcasecmp(ptr->server_type, "shadowsocks") == 0){
        ptr->extra = hl_config_extra_ss_parse(config->method,config->obfs,config->obfs_param,config->over_tls_verify,config->over_tls_root_cert_file);
    }
    else if (strcasecmp(ptr->server_type, "vmess") == 0){
        ptr->extra = hl_config_extra_v2ray_parse(config->method, sni, config->over_tls_path,config->over_tls_server_domain);
    }
    if (ptr->extra == NULL)
        goto error;
    return ptr;
error:
    return NULL;
}
#define SOCKS5_BUFFER_SIZE 4999
toto_outbound_ctx_ss_t *hl_outbound_ctx_ss_new(const uint8_t *cmd,
                           size_t cmd_len,
                           const uint8_t *password,
                           size_t password_len,
                           toto_cryptor_type_t cipher)
{
    toto_outbound_ctx_ss_t *ptr = malloc(sizeof(toto_outbound_ctx_ss_t));
    ptr->rbuf = toto_buffer_new_size(SOCKS5_BUFFER_SIZE);
    ptr->wbuf = toto_buffer_new_size(SOCKS5_BUFFER_SIZE);
    toto_cryptor_type_info(cipher, &ptr->key_len, &ptr->iv_len, &ptr->tag_len);
    ptr->enc_key = malloc(ptr->key_len);
    ptr->dec_key = malloc(ptr->key_len);
    ptr->ikm = malloc(ptr->key_len);
    ptr->enc_salt = malloc(ptr->key_len);
    evp_bytes_to_key(password, password_len, ptr->ikm, ptr->key_len);
    ptr->enc_iv = calloc(1, ptr->iv_len);
    ptr->dec_iv = calloc(1, ptr->iv_len);
    ptr->cmd = calloc(cmd_len, sizeof(uint8_t));
    memcpy((void *)ptr->cmd, cmd, cmd_len);
    ptr->cmd_len = cmd_len;
    ptr->cipher = cipher;
    ptr->iv_sent = false;
    ptr->aead_decode_state = READY;
    ptr->plen = 0;
    if (is_aead_cipher(cipher)) {
        hl_rand_bytes(ptr->enc_salt, ptr->key_len);
        hkdf_sha1(ptr->enc_salt, ptr->key_len, ptr->ikm, ptr->key_len,  (const uint8_t *)SS_INFO, 9, ptr->enc_key, ptr->key_len);
    } else {
        memcpy(ptr->enc_key, ptr->ikm, ptr->key_len);
        hl_rand_bytes(ptr->enc_iv, ptr->iv_len);
    }
    ptr->encryptor = toto_cryptor_new(cipher, TOTOVE_ENCRYPT, ptr->enc_key, ptr->enc_iv);
    ptr->decryptor = NULL;
    return ptr;
}
static void hl_outbound_ctx_ss_free(toto_outbound_ctx_ss_t *ptr)
{
    if(ptr->cmd)
    {
        free((void *)ptr->cmd);
        ptr->cmd=NULL;
    }
    if (ptr->wbuf)
        toto_buffer_free(ptr->wbuf);
    if (ptr->rbuf)
        toto_buffer_free(ptr->rbuf);
    if (ptr->encryptor)
        toto_cryptor_free(ptr->encryptor);
    if (ptr->decryptor)
        toto_cryptor_free(ptr->decryptor);
    if (ptr->enc_iv)
        free(ptr->enc_iv);
    if (ptr->enc_key)
        free(ptr->enc_key);
    if (ptr->dec_iv)
        free(ptr->dec_iv);
    if (ptr->dec_key)
        free(ptr->dec_key);
    if (ptr->ikm)
        free(ptr->ikm);
    if (ptr->enc_salt)
        free(ptr->enc_salt);
    if (ptr)
        free(ptr);
}
static toto_config_extra_ss_t *toto_config_extra_ss_new(void)
{
    toto_config_extra_ss_t *ptr = malloc(sizeof(toto_config_extra_ss_t));
    ptr->obfs = NULL;
    ptr->obfs_host = NULL;
    ptr->method = AEAD_CHACHA20_POLY1305;
    return ptr;
}
void toto_config_extra_ss_free(toto_config_extra_ss_t *ptr)
{
    free(ptr);
    ptr = NULL;
}
static toto_config_extra_ss_t *hl_config_extra_ss_parse(const char *method,const char *obfs,const char *obfs_host,bool sslVerify,const char *certfile)
{
    toto_config_extra_ss_t *ptr = toto_config_extra_ss_new();
    if (method != NULL) {
        if (strcasecmp(method, "aes-128-cfb") == 0) {
            ptr->method = AES_128_CFB;
        } else if (strcasecmp(method, "aes-128-gcm") == 0) {
            ptr->method = AEAD_AES_128_GCM;
        } else if (strcasecmp(method, "aes-256-gcm") == 0) {
            ptr->method = AEAD_AES_256_GCM;
        } else if (strcasecmp(method, "chacha20-poly1305") == 0) {
            ptr->method = AEAD_CHACHA20_POLY1305;
        }
    }
    ptr->obfs = obfs;
    ptr->obfs_host = obfs_host;
    ptr->ssl_crt=certfile;
    ptr->ssl_verify=sslVerify;
    return ptr;
}
void hl_init_outbound_ssl(toto_session_outbound_t *outbound, int fd){
    hl_outbound_ssl_init(outbound,fd);
}
uint8_t* hl_totovpn_encrypt_remote_data(toto_session_outbound_t *outbound, const uint8_t *msg, size_t len, size_t *olen){
    toto_outbound_ctx_ss_t *ssctx = outbound->ctx;
    if (is_aead_cipher(ssctx->cipher)) {
        if (hl_encrypt_shadowsocks_data(outbound, msg, len, olen)) {
            return ssctx->wbuf->buffer;
        }
        else
            return NULL;
    } else {
        return NULL;
    }
}
static bool hl_encrypt_shadowsocks_data(toto_session_outbound_t *outbound, const uint8_t *msg, size_t len,  size_t *olen)
{
    toto_outbound_ctx_ss_t *ssctx =(toto_outbound_ctx_ss_t *)outbound->ctx;
    size_t addr_len = ssctx->cmd_len - 3;
    size_t payload_len = len;
    size_t offset = 0;
    if (!ssctx->iv_sent) {
        const uint8_t *salt = ssctx->enc_salt;
        size_t salt_len = ssctx->key_len;
        toto_buffer_ensure(ssctx->wbuf, salt_len);
        memcpy(ssctx->wbuf->buffer, salt, salt_len); 
        offset += salt_len;
        payload_len = len + addr_len; 
    }
    if (payload_len > 0x3FFF) { 
        printf("!!!!hl_encrypt_shadowsocks_data>payload_len>too-Long\n");
        return false;
    }
    uint8_t prefix[2] = { 0 };
    prefix[0] = payload_len >> 8;
    prefix[1] = payload_len;
    toto_buffer_ensure(ssctx->wbuf, offset + 2 + ssctx->tag_len);
    size_t ciphertext_len;
    toto_cryptor_encrypt(ssctx->encryptor, prefix, 2,
                ssctx->wbuf->buffer + offset + 2 ,
                ssctx->wbuf->buffer + offset, &ciphertext_len);
    totovmess_ss_increase_cryptor_iv(ssctx, TOTOVE_ENCRYPT);
    if (ciphertext_len != 2) {
        return false;
    }
    offset += (2 + ssctx->tag_len); 
    if (offset + payload_len + ssctx->tag_len > 0x3FFF) { 
        printf("!!!!hl_encrypt_shadowsocks_data>the_whole_len>too-Long\n");
        return false;
    }
    if (!ssctx->iv_sent) {
        uint8_t *payload = malloc(payload_len);
        memcpy(payload, ssctx->cmd + 3, addr_len); 
        if(msg!=NULL && len>0){
            memcpy(payload + addr_len, msg, len); 
        }
        toto_buffer_ensure(ssctx->wbuf,offset + payload_len + ssctx->tag_len);
        bool ok = toto_cryptor_encrypt(
            ssctx->encryptor, payload, payload_len,
            ssctx->wbuf->buffer + offset + payload_len ,
            ssctx->wbuf->buffer + offset, &ciphertext_len);
        totovmess_ss_increase_cryptor_iv(ssctx, TOTOVE_ENCRYPT);
        free(payload);
        ssctx->iv_sent = true;
        if (!ok || ciphertext_len != payload_len) {
            return false;
        }
    } else {
        toto_buffer_ensure(ssctx->wbuf, offset + payload_len + ssctx->tag_len);
        bool ok = toto_cryptor_encrypt(
            ssctx->encryptor, msg, payload_len,
            ssctx->wbuf->buffer + offset + payload_len ,
            ssctx->wbuf->buffer + offset, &ciphertext_len); 
        totovmess_ss_increase_cryptor_iv(ssctx, TOTOVE_ENCRYPT);
        if (!ok || ciphertext_len != payload_len) {
            return false;
        }
    }
    *olen = offset + payload_len + ssctx->tag_len;
    return true;
}
bool hl_totovpn_decrypt_local_data(toto_session_outbound_t *outbound, const uint8_t *msg,size_t len, size_t *olen, size_t *clen){
    toto_outbound_ctx_ss_t *ssctx = outbound->ctx;
    if (is_aead_cipher(ssctx->cipher)) {
        return hl_decrypt_shadowsocks_data(outbound, msg, len, olen, clen);
    } else {
        return false; 
    }
}
static bool hl_decrypt_shadowsocks_data(toto_session_outbound_t *outbound, const uint8_t *msg, size_t len, size_t *olen, size_t *clen){
    toto_outbound_ctx_ss_t *ssctx = (toto_outbound_ctx_ss_t *)outbound->ctx;
    *clen = 0;
    size_t offset=0;
    size_t decode_len;
    if (!ssctx->decryptor) {
        if (len < ssctx->key_len) {
            printf("!!!need atl least %ld bytes for salt!\n",ssctx->key_len);
            return false;
        }
        hkdf_sha1(msg , ssctx->key_len, ssctx->ikm,ssctx->key_len, (const uint8_t *)SS_INFO, 9,ssctx->dec_key, ssctx->key_len);
        ssctx->decryptor = toto_cryptor_new(ssctx->cipher, TOTOVE_DECRYPT,  ssctx->dec_key, ssctx->dec_iv);
        offset+=ssctx->key_len;
        *clen=offset;
        len -= ssctx->key_len;
    }
    assert(ssctx->decryptor);
    while (true) {
        switch (ssctx->aead_decode_state) {
            case READY: {
                if (ssctx->plen == 0) {
                    if (len < 2 + ssctx->tag_len) { 
                        ssctx->aead_decode_state = WAIT_MORE_FOR_LEN;
                        printf("!!!need more data for payload len :%zu\n",len);
                        return true;
                    }
                    uint8_t chunk_len[2];
                    toto_cryptor_decrypt(ssctx->decryptor,msg + offset, 2,msg + offset + 2, chunk_len,&decode_len);
                    totovmess_ss_increase_cryptor_iv(ssctx, TOTOVE_DECRYPT);
                    if (decode_len != 2) {
                        return false;
                    }
                    offset += (2 + ssctx->tag_len); 
                    len -= (2 + ssctx->tag_len);
                    ssctx->plen = (uint16_t)chunk_len[0] << 8 | chunk_len[1];
                    if (0==ssctx->plen) { 
                        if (len>=ssctx->tag_len) {
                            offset += ssctx->tag_len; 
                            *clen=offset; 
                            len-=ssctx->tag_len;
                            if (0==len) {
                                printf("is null payload!!!\n");
                                return true;
                            }
                        }else{
                            ssctx->aead_decode_state = WAIT_MORE_FOR_LEN;
                            printf("!!!need more data for payload len :%zu\n",len);
                            return true;
                        }
                    }
                    else if (ssctx->plen>0x3FFF){
                        printf("!!!payload-len too long\n");
                        return false;
                    }
                } else {
                    if (len < ssctx->plen + ssctx->tag_len) { 
                        ssctx->aead_decode_state = WAIT_MORE_FOR_PAYLOAD;
                        printf("!!!need more data for payload\n");
                        return true;
                    }
                    toto_buffer_ensure(ssctx->rbuf, ssctx->plen);
                    toto_cryptor_decrypt(ssctx->decryptor,msg + offset, ssctx->plen,msg + offset + ssctx->plen,ssctx->rbuf->buffer,&decode_len);
                    totovmess_ss_increase_cryptor_iv(ssctx, TOTOVE_DECRYPT);
                    if (decode_len != ssctx->plen) {
                        printf("!!!decode_len != ssctx->plen\n");
                        return false;
                    }
                    if (outbound->outbound_socket_ctx_write_fn) { 
                        uint8_t *buf_data=ssctx->rbuf->buffer;
                        size_t buf_len=ssctx->plen;
                        outbound->outbound_socket_ctx_write_fn(outbound,buf_data,buf_len,true);
                    }
                    *olen += ssctx->plen;
                    offset += (ssctx->plen + ssctx->tag_len);
                    *clen=offset;
                    len -= (ssctx->plen + ssctx->tag_len);
                    ssctx->plen = 0;
                }
                break;
            }
            case WAIT_MORE_FOR_LEN: {
                if (len < 2 + ssctx->tag_len) {
                    return true;
                }
                ssctx->aead_decode_state = READY;
                break;
            }
            case WAIT_MORE_FOR_PAYLOAD: {
                if (len < ssctx->plen + ssctx->tag_len) {
                    return true;
                }
                if (0==offset) {
                    offset += (2 + ssctx->tag_len);
                    len -= (2 + ssctx->tag_len);
                }
                ssctx->aead_decode_state = READY;
                break;
            }
            default:
                printf("!!!unkonw state when decrypt\n");
                break;
        } 
    } 
}
static void totovmess_ss_increase_cryptor_iv(toto_outbound_ctx_ss_t *ctx,toto_cryptor_direction_t dir){
    if (is_aead_cipher(ctx->cipher)) {
        toto_cryptor_t *cryptor = NULL;
        uint8_t *iv = NULL;
        switch (dir) {
        case TOTOVE_DECRYPT:
            cryptor = ctx->decryptor;
            iv = ctx->dec_iv;
            break;
        case TOTOVE_ENCRYPT:
            cryptor = ctx->encryptor;
            iv = ctx->enc_iv;
            break;
        default:
            break;
        }
        if (iv != NULL && cryptor != NULL) {
            totovmess_increase_nonce(iv, ctx->iv_len); 
            toto_cryptor_reset_iv(cryptor, iv);
        }
    }
}
