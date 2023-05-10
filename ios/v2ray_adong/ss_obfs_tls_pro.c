#include "ss_obfs_tls_pro.h"
#include <strings.h>
#include <time.h>
#include <libcork/core.h>
#include "ssrbuffer.h"
#define CT_HTONS(n) CORK_UINT16_HOST_TO_BIG(n)
#define CT_NTOHS(n) CORK_UINT16_BIG_TO_HOST(n)
#define CT_HTONL(n) CORK_UINT32_HOST_TO_BIG(n)
#define CT_NTOHL(n) CORK_UINT32_BIG_TO_HOST(n)
static const struct tls_client_hello
tls_client_hello_template = {
    .content_type = 0x16,
    .version =CT_HTONS(0x0301), 
    .len = 0,
    .handshake_type = 1,
    .handshake_len_1 = 0,
    .handshake_len_2 = 0,
    .handshake_version = CT_HTONS(0x0303),
    .random_unix_time = 0,
    .random_bytes = { 0 },
    .session_id_len = 32,
    .session_id = { 0 },
    .cipher_suites_len = CT_HTONS(56), 
    .cipher_suites = {
        0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0, 0x2f,
        0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67, 0xc0, 0x0a,
        0xc0, 0x14, 0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00, 0x9c, 0x00, 0x3d,
        0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff
    },
    .comp_methods_len = 1,
    .comp_methods = { 0 },
    .ext_len = 0,
};
static const struct tls_ext_server_name_info
tls_ext_server_name_template = {
    .ext_type = 0,
    .ext_len = 0,
    .server_name_list_len = 0,
    .server_name_type = 0,
    .server_name_len = 0,
};
static const struct tototls_ext_session_ticket
tototls_ext_session_ticket_template = {
    .session_ticket_type = CT_HTONS(0x0023),
    .session_ticket_ext_len = 0,
};
static const struct tototls_ext_others
tototls_ext_others_template = {
    .ec_point_formats_ext_type = CT_HTONS(0x000B),
    .ec_point_formats_ext_len = CT_HTONS(4),
    .ec_point_formats_len = 3,
    .ec_point_formats = { 0x01, 0x00, 0x02 },
    .elliptic_curves_type = CT_HTONS(0x000a),
    .elliptic_curves_ext_len = CT_HTONS(10),
    .elliptic_curves_len = CT_HTONS(8),
    .elliptic_curves = { 0x00, 0x1d, 0x00, 0x17, 0x00, 0x19, 0x00, 0x18 },
    .sig_algos_type = CT_HTONS(0x000d),
    .sig_algos_ext_len = CT_HTONS(32),
    .sig_algos_len = CT_HTONS(30),
    .sig_algos = {
        0x06, 0x01, 0x06, 0x02, 0x06, 0x03, 0x05, 0x01, 0x05, 0x02, 0x05, 0x03, 0x04, 0x01, 0x04, 0x02,
        0x04, 0x03, 0x03, 0x01, 0x03, 0x02, 0x03, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x03
    },
    .encrypt_then_mac_type = CT_HTONS(0x0016),
    .encrypt_then_mac_ext_len = 0,
    .extended_master_secret_type = CT_HTONS(0x0017),
    .extended_master_secret_ext_len = 0,
};
static const struct tototls_server_hello
tototls_server_hello_template = {
    .content_type = 0x16,
    .version = CT_HTONS(0x0301), 
    .len = CT_HTONS(91),
    .handshake_type = 2,
    .handshake_len_1 = 0,
    .handshake_len_2 = CT_HTONS(87),
    .handshake_version = CT_HTONS(0x0303),  
    .random_unix_time = 0,
    .random_bytes = { 0 },
    .session_id_len = 32,
    .session_id = { 0 },
    .cipher_suite = CT_HTONS(0xCCA8),
    .comp_method = 0,
    .ext_len = 0,
    .ext_renego_info_type = CT_HTONS(0xFF01),
    .ext_renego_info_ext_len = CT_HTONS(1),
    .ext_renego_info_len = 0,
    .extended_master_secret_type = CT_HTONS(0x0017),
    .extended_master_secret_ext_len = 0,
    .ec_point_formats_ext_type = CT_HTONS(0x000B),
    .ec_point_formats_ext_len = CT_HTONS(2),
    .ec_point_formats_len = 1,
    .ec_point_formats = { 0 },
};
typedef struct buffer_t {
    size_t len;
    size_t capacity;
    uint8_t *buffer;
    int ref_count;
}buffer_t_t;
const uint8_t ss_tls_data_header[3] = {0x17, 0x03, 0x03}; 
#define SS_MAX_BUF_SIZE 16384  
static int decode_ss_tls_data(buffer_t_t *buf, ss_obfs_stage_t *obfs,size_t iv_len,size_t *olen);
static int rand_bytes(void *output, int len);
size_t ss_obfs_tls_req_package(struct buffer_t *buf, ss_obfs_stage_t *obfs){
    if (obfs == NULL || obfs->obfs_stage < 0) return 0;
    if (obfs->obfs_stage==0) {
        size_t buf_len = buf->len; 
        size_t hello_len = sizeof(struct tls_client_hello);  
        size_t server_name_len = sizeof(struct tls_ext_server_name_info);  
        size_t host_len = strlen(obfs->host); 
        size_t ticket_len = sizeof(struct tototls_ext_session_ticket); 
        size_t other_ext_len = sizeof(struct tototls_ext_others); 
        size_t tls_len = buf_len + hello_len + server_name_len + host_len + ticket_len + other_ext_len; 
        buffer_t_t *tmpData=buffer_create(buf->len);
        buffer_replace(tmpData, buf); 
        buffer_realloc(buf, tls_len); 
        memset(buf->buffer, 0, tls_len);
        struct tls_client_hello *hello = (struct tls_client_hello *)buf->buffer;
        memcpy(hello, &tls_client_hello_template, hello_len); 
        hello->len = CT_HTONS(tls_len - 5); 
        hello->handshake_len_2 = CT_HTONS(tls_len - 9);
        hello->random_unix_time = CT_HTONL((uint32_t)time(NULL)); 
        rand_bytes(hello->random_bytes, 28);
        rand_bytes(hello->session_id, 32);
        hello->ext_len = CT_HTONS(server_name_len + host_len + ticket_len + buf_len + other_ext_len);
        struct tototls_ext_session_ticket *ticket = (struct tototls_ext_session_ticket *)((char *)hello + hello_len); 
        memcpy(ticket, &tototls_ext_session_ticket_template, sizeof(struct tototls_ext_session_ticket));
        ticket->session_ticket_ext_len = CT_HTONS(buf_len);
        if (tmpData!=NULL && tmpData->buffer!=NULL && buf_len>0) {
            memcpy((char *)ticket + ticket_len,tmpData->buffer, buf_len); 
            buffer_release(tmpData);
        }
        struct tls_ext_server_name_info *server_name = (struct tls_ext_server_name_info *)((char *)ticket + ticket_len + buf_len); 
        memcpy(server_name, &tls_ext_server_name_template, server_name_len);
        server_name->ext_len = CT_HTONS(host_len + 3 + 2);
        server_name->server_name_list_len = CT_HTONS(host_len + 3);
        server_name->server_name_len = CT_HTONS(host_len);
        memcpy((char *)server_name + server_name_len, obfs->host, host_len); 
        memcpy((char *)server_name + server_name_len + host_len, &tototls_ext_others_template, other_ext_len); 
        buf->len = tls_len;
        obfs->obfs_stage++;
    }
    else{
        size_t buf_len = buf->len;
        buffer_realloc(buf, buf_len + 5); 
        buf->len = buf_len + 5;
        memmove(buf->buffer + 5, buf->buffer, buf_len); 
        memcpy(buf->buffer, ss_tls_data_header, 3);
        *(uint16_t*)(buf->buffer + 3) = CT_HTONS(buf_len);
    }
    return buf->len;
}
int ss_obfs_tls_rsp_package(struct buffer_t *buf, ss_obfs_stage_t *obfs,size_t *olen)
{
    if (obfs == NULL || obfs->deobfs_stage < 0)
        return false;
    if (obfs->extra == NULL) {
        obfs->extra = (frame_t*)calloc(1, sizeof(frame_t));
    }
    frame_t *frame = (frame_t *)obfs->extra;
    if (obfs->deobfs_stage == 0) {
        size_t len = buf->len;
        uint8_t *data = buf->buffer;
        size_t hello_len = sizeof(struct tototls_server_hello);
        len -= hello_len;
        if (len <= 0){
            printf("!!!ss_obfs_tls_rsp_package-err>buf_len<hello_len\n");
            return OBFS_TLS_ERROR;
        }
        struct tototls_server_hello *hello = (struct tototls_server_hello*) data;
        if (hello->content_type != tototls_server_hello_template.content_type){
            printf("!!!ss_obfs_tls_rsp_package-err>err_hello_content\n");
            return OBFS_TLS_ERROR;
        }
        size_t change_cipher_spec_len = sizeof(struct tototls_change_cipher_spec);
        size_t encrypted_handshake_len = sizeof(struct tototls_encrypted_handshake);
        len -= change_cipher_spec_len + encrypted_handshake_len;
        if (len <= 0){
            printf("!!!ss_obfs_tls_rsp_package-err>buf_len<encrypted_handshake_len\n");
            return OBFS_TLS_ERROR;
        }
        size_t tls_len = hello_len + change_cipher_spec_len + encrypted_handshake_len;
        struct tototls_encrypted_handshake *encrypted_handshake = (struct tototls_encrypted_handshake *)(buf->buffer + hello_len + change_cipher_spec_len);
        size_t msg_len = CT_NTOHS(encrypted_handshake->len); 
        buffer_shortened_to(buf, tls_len, buf->len-tls_len, true); 
        obfs->deobfs_stage++; 
        if (buf->len<msg_len) {
            printf("!!!ss_obfs_tls_rsp_package-err>buf_len<msg_len\n");
            return OBFS_TLS_ERROR;
        }else if (buf->len==msg_len){
            *olen=msg_len;
            frame->ilastState=OBFS_TLS_OK;
            return OBFS_TLS_OK;
        }
        else{
            frame->ilastState=OBFS_TLS_OK;
            return decode_ss_tls_data(buf, obfs,msg_len,olen);
        }
    }
    else{
        return decode_ss_tls_data(buf,obfs,0,olen);
    }
}
static int decode_ss_tls_data(buffer_t_t *buf, ss_obfs_stage_t *obfs,size_t iv_len,size_t *olen)
{
    size_t tls_header_len = 5;
    frame_t *frame = (frame_t *)obfs->extra;
    size_t buf_index=iv_len;
    *olen=iv_len;
    while (buf->len-buf_index>0) {
        if (frame->ilastState != OBFS_TLS_NEED_MORE_DATA) {
            if (buf->len<buf_index+tls_header_len) {
                printf("decode_ss_tls_data>need-more-header\n");
                frame->ilastState=OBFS_TLS_NEED_MORE_HEAD;
                return OBFS_TLS_NEED_MORE_HEAD;
            }
            if ( buf->buffer[buf_index+0]!=ss_tls_data_header[0] ||  buf->buffer[buf_index+1]!=ss_tls_data_header[1] ||  buf->buffer[buf_index+2]!=ss_tls_data_header[2]) {
                printf("decode_ss_tls_data>err_tls_frame_header\n");
                frame->ilastState=OBFS_TLS_ERROR;
                return OBFS_TLS_ERROR; 
            }
            memcpy(frame->data_len_buf, buf->buffer+buf_index+3, 2);
            frame->len = CT_NTOHS(*(uint16_t *)(frame->data_len_buf));
            if (frame->len > SS_MAX_BUF_SIZE){
                printf("decode_ss_tls_data>too-long>%d\n",frame->len);
                frame->ilastState=OBFS_TLS_ERROR;
                return OBFS_TLS_ERROR;
            }
            else if (frame->len<=0){
                printf("decode_ss_tls_data>err-long>%d\n",frame->len);
                frame->ilastState=OBFS_TLS_ERROR;
                return OBFS_TLS_ERROR;
            }
        }
        size_t  left_len = buf->len - buf_index - tls_header_len;
        if (left_len<frame->len) {
            frame->ilastState=OBFS_TLS_NEED_MORE_DATA;
            return OBFS_TLS_NEED_MORE_DATA;
        }
        else{
            memmove(buf->buffer+buf_index, buf->buffer+buf_index+tls_header_len, buf->len-buf_index-tls_header_len); 
            buf->len=buf->len-tls_header_len;
            buf_index+=frame->len; 
            *olen=buf_index;  
            frame->len=0;
            frame->ilastState=OBFS_TLS_OK; 
            memset(frame->data_len_buf, 0, 2);
        }
    }
    return OBFS_TLS_OK;
}
static int rand_bytes(void *output, int len)
{
    int i;
    int *array = (int *)output;
    for (i = 0; i < len / sizeof(int); i++)
        array[i] = rand();
    return 0;
}
