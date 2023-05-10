#ifndef vmessPro_h
#define vmessPro_h
#include <stdio.h>
#include "vmessCrypto.h"
#include "vmessTools.h"
#include "vmess_ssl_pro.h"
#include "ssr_executive.h"
struct tunnel_ctx;
#define SS_INFO "ss-subkey"
toto_session_outbound_t *hl_session_outbound_new(void);
void hl_session_outbound_free(toto_session_outbound_t *ptr);
toto_outbound_ctx_v2ray_t *hl_outbound_ctx_v2ray_new(const uint8_t *cmd, size_t cmdlen, toto_cryptor_type_t cipher);
bool hl_vmess_write_data_2_remote(toto_session_outbound_t *outbound,const uint8_t *data,size_t data_len);
toto_server_config_t *hl_config_parse_servers(struct server_config* config);
bool hl_vmess_write_data_2_local(toto_session_outbound_t *outbound, const uint8_t *data,
                       size_t data_len, size_t *olen);
uint8_t * hl_decode_vemss_data(toto_session_outbound_t *outbound, const uint8_t *data,
                       size_t data_len, size_t *olen);
toto_outbound_ctx_ss_t *hl_outbound_ctx_ss_new(const uint8_t *cmd,
                           size_t cmd_len,
                           const uint8_t *password,
                           size_t password_len,
                           toto_cryptor_type_t cipher);
void hl_init_outbound_ssl(toto_session_outbound_t *outbound, int fd);
uint8_t* hl_totovpn_encrypt_remote_data(toto_session_outbound_t *outbound, const uint8_t *msg,
                  size_t len, size_t *olen);
bool hl_totovpn_decrypt_local_data(toto_session_outbound_t *outbound, const uint8_t *msg,
                 size_t len, size_t *olen, size_t *clen);
#endif 
