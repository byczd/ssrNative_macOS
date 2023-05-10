#ifndef ss_obfs_tls_pro_h
#define ss_obfs_tls_pro_h
#include <stdio.h>
struct buffer_t;
typedef struct ss_obfs_stage {
    int obfs_stage;
    int deobfs_stage;
    char *host;
    struct buffer_t *buf;
    void *extra;  
} ss_obfs_stage_t;
typedef struct frame {
    short ilastState;
    short len;
    char  data_len_buf[2];
} frame_t;
struct tls_client_hello {
    char  content_type;
    short version;
    short len;
    char  handshake_type;
    char  handshake_len_1;
    short handshake_len_2;
    short handshake_version;
    int   random_unix_time;
    char  random_bytes[28];
    char  session_id_len;
    char  session_id[32];
    short cipher_suites_len;
    char  cipher_suites[56];
    char  comp_methods_len;
    char  comp_methods[1];
    short ext_len;
} __attribute__((packed, aligned(1)));
struct tls_ext_server_name_info {
    short ext_type;
    short ext_len;
    short server_name_list_len;
    char  server_name_type;
    short server_name_len;
} __attribute__((packed, aligned(1)));
struct tototls_ext_session_ticket {
    short session_ticket_type;
    short session_ticket_ext_len;
} __attribute__((packed, aligned(1)));
struct tototls_ext_others {
    short ec_point_formats_ext_type;
    short ec_point_formats_ext_len;
    char  ec_point_formats_len;
    char  ec_point_formats[3];
    short elliptic_curves_type;
    short elliptic_curves_ext_len;
    short elliptic_curves_len;
    char  elliptic_curves[8];
    short sig_algos_type;
    short sig_algos_ext_len;
    short sig_algos_len;
    char  sig_algos[30];
    short encrypt_then_mac_type;
    short encrypt_then_mac_ext_len;
    short extended_master_secret_type;
    short extended_master_secret_ext_len;
} __attribute__((packed, aligned(1)));
struct tototls_server_hello {
    char  content_type;
    short version;
    short len;
    char  handshake_type;
    char  handshake_len_1;
    short handshake_len_2;
    short handshake_version;
    int   random_unix_time;
    char  random_bytes[28];
    char  session_id_len;
    char  session_id[32];
    short cipher_suite;
    char  comp_method;
    short ext_len;
    short ext_renego_info_type;
    short ext_renego_info_ext_len;
    char  ext_renego_info_len;
    short extended_master_secret_type;
    short extended_master_secret_ext_len;
    short ec_point_formats_ext_type;
    short ec_point_formats_ext_len;
    char  ec_point_formats_len;
    char  ec_point_formats[1];
} __attribute__((packed, aligned(1)));
struct tototls_change_cipher_spec {
    char  content_type;
    short version;
    short len;
    char  msg;
} __attribute__((packed, aligned(1)));
struct tototls_encrypted_handshake {
    char  content_type;
    short version;
    short len;
} __attribute__((packed, aligned(1)));
#define OBFS_TLS_OK         0
#define OBFS_TLS_ERROR     -1
#define OBFS_TLS_NEED_MORE_DATA     -2
#define OBFS_TLS_NEED_MORE_HEAD     -3
size_t ss_obfs_tls_req_package(struct buffer_t *buf, ss_obfs_stage_t *obfs);
typedef void (*ss_decode_response_data_cb)(struct buffer_t* buf,void *tunnel); 
int ss_obfs_tls_rsp_package(struct buffer_t *buf, ss_obfs_stage_t *obfs,size_t *olen);
#endif 
