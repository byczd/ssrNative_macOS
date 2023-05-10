//ssLocalClient

#include "base64.h"
#include "common.h"
#include <c_stl_lib.h>
#include "defs.h"
#include "dump_info.h"
#include "encrypt.h"
#include "http_parser_wrapper.h"
#include "obfs.h"
#include "obfsutil.h"
#include "s5.h"
#include "ssr_executive.h"
#include "ssrbuffer.h"
#include "tls_cli.h"
#include "tunnel.h"
#include "udprelay.h"
#include "websocket_basic.h"
#include <ssrutils.h>
#include <string.h>

#include "vmessPro.h"

//----------ss
//#include "obfs_http.h"
//#include "obfs_tls.h"
//#include "ss_buf_pro.h"
//#include "aead.h"

#include "ss_obfs_tls_pro.h"

//--vmess
//#include "vmessClient.h"

//#include "service.h"

/* Session states. */
#define TUNNEL_STAGE_MAP(V)                                                                                                                     \
    V( 0, tunnel_stage_handshake,                   "tunnel_stage_handshake -- Client App S5 handshake coming.")                                \
    V( 1, tunnel_stage_handshake_replied,           "tunnel_stage_handshake_replied -- Start waiting for request data.")                        \
    V( 2, tunnel_stage_s5_request_from_client_app,  "tunnel_stage_s5_request_from_client_app -- SOCKS5 Request data from client app.")          \
    V( 3, tunnel_stage_s5_udp_accoc,                "tunnel_stage_s5_udp_accoc")                                                                \
    V( 4, tunnel_stage_s5_response_done,            "tunnel_stage_s5_response_done")                                                            \
    V( 5, tunnel_stage_client_first_pkg,            "tunnel_stage_client_first_pkg")                                                            \
    V( 6, tunnel_stage_tls_connecting,              "tunnel_stage_tls_connecting")                                                              \
    V( 7, tunnel_stage_tls_websocket_upgrade,       "tunnel_stage_tls_websocket_upgrade")                                                       \
    V( 8, tunnel_stage_tls_streaming,               "tunnel_stage_tls_streaming")                                                               \
    V( 9, tunnel_stage_resolve_ssr_server_host_done,"tunnel_stage_resolve_ssr_server_host_done -- Upstream hostname DNS lookup has completed.") \
    V(10, tunnel_stage_connect_ssr_server_done,     "tunnel_stage_connect_ssr_server_done -- Connect to server complete.")                      \
    V(11, tunnel_stage_ssr_auth_sent,               "tunnel_stage_ssr_auth_sent")                                                               \
    V(12, tunnel_stage_ssr_server_feedback_arrived, "tunnel_stage_ssr_server_feedback_arrived")                                                 \
    V(13, tunnel_stage_ssr_receipt_to_server_sent,  "tunnel_stage_ssr_receipt_to_server_sent")                                                  \
    V(14, tunnel_stage_auth_completion_done,        "tunnel_stage_auth_completion_done -- Auth succeeded. Can start piping data.")              \
    V(15, tunnel_stage_streaming,                   "tunnel_stage_streaming -- Pipe data back and forth.")                                      \
    V(16, tunnel_stage_kill,                        "tunnel_stage_kill -- Tear down session.")                                                  \

/*
 ws协议常量
 */
const char *ws_upgrade = "HTTP/1.1 101";
const char *ws_key = "dGhlIHNhbXBsZSBub25jZQ==";  //the sample nonce
const char *ws_accept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

enum tunnel_stage {
#define TUNNEL_STAGE_GEN(code, name, _) name = code,
    TUNNEL_STAGE_MAP(TUNNEL_STAGE_GEN)
#undef TUNNEL_STAGE_GEN
    tunnel_stage_max,
};

static const char* tunnel_stage_string(enum tunnel_stage stage) {
#define TUNNEL_STAGE_GEN(_, name, name_str) case name: return name_str;
    switch (stage) {
        TUNNEL_STAGE_MAP(TUNNEL_STAGE_GEN)
        default:
            return "Unknown stage.";
    }
#undef TUNNEL_STAGE_GEN
}

struct client_ctx;

struct udp_data_context {
    union sockaddr_universal src_addr;
    struct socks5_address target_addr;
    struct cstl_deque* send_deque; // std::deque<struct buffer_t *>
    struct cstl_deque* recv_deque;

    struct client_ctx* owner; // __weak_ptr
    struct client_ssrot_udp_listener_ctx* udp_ctx; // __weak_ptr
};

struct udp_data_context* udp_data_context_create(void);
void udp_data_context_destroy(struct udp_data_context* ptr);

struct client_ctx {
    struct tunnel_ctx* tunnel; // __weak_ptr
    struct server_env_t* env; // __weak_ptr
    struct tunnel_cipher_ctx* cipher;
    struct buffer_t* init_pkg;
    struct buffer_t* first_client_pkg;
    struct s5_ctx* parser; /* The SOCKS protocol parser. */
    enum tunnel_stage stage;
    void (*original_tunnel_shutdown)(struct tunnel_ctx* tunnel); /* ptr holder */
    char* sec_websocket_key;
    struct buffer_t* server_delivery_cache;
    struct buffer_t* local_write_cache;
    bool tls_is_eof;
    struct tls_cli_ctx* tls_ctx;
    int connection_status;
    bool is_terminated;

    REF_COUNT_MEMBER;

    struct udp_data_context* udp_data_ctx;
};

#if ANDROID
static void stat_update_cb(void) {
    if (log_tx_rx) {
        uint64_t _now = uv_hrtime();
        if (_now - last > 1000) {
            send_traffic_stat(tx, rx);
            last = _now;
        }
    }
}
#endif

REF_COUNT_ADD_REF_DECL(client_ctx); // client_ctx_add_ref
REF_COUNT_RELEASE_DECL(client_ctx); // client_ctx_release

static struct buffer_t* initial_package_create(const struct s5_ctx* parser);
static void tunnel_ssr_dispatcher(struct tunnel_ctx* tunnel, struct socket_ctx* socket);
//static void tunnel_tls_dispatcher(struct tunnel_ctx* tunnel, struct socket_ctx* socket);
static void do_handshake(struct tunnel_ctx* tunnel);
static void do_wait_client_app_s5_request(struct tunnel_ctx* tunnel);
static void do_parse_s5_request_from_client_app(struct tunnel_ctx* tunnel,int proxyType);
static void do_common_connet_remote_server(struct tunnel_ctx* tunnel);
static void do_resolve_ssr_server_host_aftercare(struct tunnel_ctx* tunnel);
static void do_connect_ssr_server(struct tunnel_ctx* tunnel);
static void do_ssr_send_auth_package_to_server(struct tunnel_ctx* tunnel);
static void do_ssr_waiting_server_feedback(struct tunnel_ctx* tunnel);

static bool do_ssr_receipt_for_feedback(struct tunnel_ctx* tunnel);
static void do_socks5_reply_success(struct tunnel_ctx* tunnel);
static void do_action_after_auth_server_success(struct tunnel_ctx* tunnel);
static void do_launch_streaming(struct tunnel_ctx* tunnel);
static void tunnel_ssr_client_streaming(struct tunnel_ctx* tunnel, struct socket_ctx* socket);
static uint8_t* tunnel_extract_data(struct tunnel_ctx* tunnel, struct socket_ctx* socket, void* (*allocator)(size_t size), size_t* size);
static void tunnel_destroying(struct tunnel_ctx* tunnel);
static void tunnel_timeout_expire_done(struct tunnel_ctx* tunnel, struct socket_ctx* socket);
static void tunnel_outgoing_connected_done(struct tunnel_ctx* tunnel, struct socket_ctx* socket);
static void tunnel_read_done(struct tunnel_ctx* tunnel, struct socket_ctx* socket);
static void tunnel_arrive_end_of_file(struct tunnel_ctx* tunnel, struct socket_ctx* socket);
static void tunnel_on_getaddrinfo_done(struct tunnel_ctx* tunnel, struct socket_ctx* socket, const struct addrinfo* ai);
static void tunnel_write_done(struct tunnel_ctx* tunnel, struct socket_ctx* socket);
static size_t tunnel_get_alloc_size(struct tunnel_ctx* tunnel, struct socket_ctx* socket, size_t suggested_size);
static bool tunnel_ssr_is_in_streaming(struct tunnel_ctx* tunnel);

static void tls_cli_on_connection_established(struct tls_cli_ctx* tls_cli, int status, void* p);
static void tls_cli_on_write_done(struct tls_cli_ctx* tls_cli, int status, void* p);
static void tls_cli_on_data_received(struct tls_cli_ctx* tls_cli, int status, const uint8_t* data, size_t size, void* p);

static void tls_cli_send_websocket_data(struct client_ctx* ctx, const uint8_t* buf, size_t len);

static bool can_auth_none(const struct tunnel_ctx* cx);
static bool can_auth_passwd(const struct tunnel_ctx* cx);
static bool can_access(const struct tunnel_ctx* cx, const struct sockaddr* addr);

static bool tunnel_is_terminated(struct tunnel_ctx* tunnel);
static void tunnel_shutdown(struct tunnel_ctx* tunnel);

//---------------vmess.add.by.adong
static bool isVMessConfig(struct server_config* config);

static void tunnel_vmess_dispatcher(struct tunnel_ctx* tunnel, struct socket_ctx* socket);
static bool tunnel_vmess_is_in_streaming(struct tunnel_ctx* tunnel);
static void vmess_init_outbound(struct tunnel_ctx* tunnel,const uint8_t* data,size_t size);
static void vmess_myabe_ws_ssl_handshake(struct tunnel_ctx* tunnel);
static void vmess_waiting_ws_server_feedback(struct tunnel_ctx* tunnel);
static void vmess_prase_websocket_feedback(struct tunnel_ctx* tunnel);
static bool vmess_ws_upgrade_check(const char *data);
static void vmess_send_first_package(struct tunnel_ctx* tunnel);
static void tunnel_vmess_client_streaming(struct tunnel_ctx* tunnel, struct socket_ctx* socket);

static void vmess_socket_write_data(toto_session_outbound_t* outbound, const void* data, size_t len,bool is2Local);
static void vmess_ws_write_frame_2_remtoe(struct tunnel_ctx* tunnel, const uint8_t* vmess_buf, size_t vmess_len);
static void vmess_ws_decode_recv_data(struct tunnel_ctx* tunnel,uint8_t* data, size_t size);

//----------ss
static bool isSSConfig(struct server_config* config);
static void tunnel_SS_dispatcher(struct tunnel_ctx* tunnel, struct socket_ctx* socket);
static void totovpn_do_ss_handshake(struct tunnel_ctx* tunnel);
static void totovpn_waiting_ss_handshake_feedback(struct tunnel_ctx* tunnel);
static void totovpn_prase_ss_handshake_feedback(struct tunnel_ctx* tunnel);
static void totovpn_init_outbound(struct tunnel_ctx* tunnel,const uint8_t* data,size_t size);
static void do_totovpn_launch_streaming(struct tunnel_ctx* tunnel);
static void tunnel_totovpn_client_streaming(struct tunnel_ctx* tunnel, struct socket_ctx* socket);
static void totovpn_send_ss_header(struct client_ctx* ctx,bool is_tls);
static void totovpn_init_obfs(struct tunnel_ctx* tunnel,bool is_tls);
static void totovpn_free_obfs(struct tunnel_ctx* tunnel);
static void totovpn_decoded_rep_data_cb(struct buffer_t* buf,void* tunnel_hd);
static void totovpn_socket_write_data(toto_session_outbound_t* outbound, const void* data, size_t len,bool is2Local);
static void totovpn_socket_write_5000_data(struct tunnel_ctx* tunnel,struct socket_ctx* incoming,const uint8_t *data,size_t len);

static bool init_done_cb(struct tunnel_ctx* tunnel, void* p) {
    struct server_env_t* env = (struct server_env_t*)p;
    struct server_config* config = env->config;

    struct client_ctx* ctx = (struct client_ctx*)calloc(1, sizeof(struct client_ctx));
    ctx->tunnel = tunnel;
    ctx->env = env;
    tunnel->data = ctx;

    client_ctx_add_ref(ctx);

    /* override the origin function tunnel_shutdown */
    ctx->original_tunnel_shutdown = tunnel->tunnel_shutdown;
    tunnel->tunnel_shutdown = &tunnel_shutdown;
    tunnel->tunnel_is_terminated = &tunnel_is_terminated;

    tunnel->tunnel_destroying = &tunnel_destroying;
    tunnel->tunnel_timeout_expire_done = &tunnel_timeout_expire_done;
    tunnel->tunnel_outgoing_connected_done = &tunnel_outgoing_connected_done;
    tunnel->tunnel_read_done = &tunnel_read_done;
    tunnel->tunnel_arrive_end_of_file = &tunnel_arrive_end_of_file;
    tunnel->tunnel_on_getaddrinfo_done = &tunnel_on_getaddrinfo_done;
    tunnel->tunnel_write_done = &tunnel_write_done;
    tunnel->tunnel_get_alloc_size = &tunnel_get_alloc_size;
    tunnel->tunnel_extract_data = &tunnel_extract_data;
    
    tunnel->is_ws_protocol=false;
    tunnel->is_tls_protocol=config->over_tls_enable;
    
    if (isVMessConfig(config)) {
        tunnel->tunnel_dispatcher = &tunnel_vmess_dispatcher;
        tunnel->tunnel_is_in_streaming = &tunnel_vmess_is_in_streaming;
//     判断是否ws
        if (strlen(config->over_tls_server_domain)>0 || strlen(config->over_tls_path)>0) {
//切记是||,over_tls_server_domain/over_tls_path有为空的情况
            tunnel->is_ws_protocol=true;
        }
//vmess下的http和ws调试成功， 而wss还没调试成功，need.update
    }
    else if (isSSConfig(config)){
        tunnel->tunnel_dispatcher = &tunnel_SS_dispatcher;
        tunnel->tunnel_is_in_streaming = &tunnel_ssr_is_in_streaming;
        
        config->over_tls_enable=false;
        if (config->obfs!=NULL) {
            if (strstr(config->obfs, "http")){
                tunnel->is_ws_protocol=true;
            }
            else if (strstr(config->obfs, "tls") && strlen(config->obfs_param)>0 ){
                tunnel->is_tls_protocol=true;
            }else{
                //tcp
            }
        }
//而ss下的obfs=tcp或tls调试成功，但obfs=ws没有成功 need.update
    }
//trojan是默认走tls的，只是看需否证书验证问题，2种都已调试OK
//    else if (config->over_tls_enable) { //是否走ssl/tls安全协议留到各自dispatcher再处理
//        tunnel->tunnel_dispatcher = &tunnel_tls_dispatcher;
//        tunnel->tunnel_is_in_streaming = &tunnel_tls_is_in_streaming;
//    }
    else { //ssr
        tunnel->tunnel_dispatcher = &tunnel_ssr_dispatcher;
        tunnel->tunnel_is_in_streaming = &tunnel_ssr_is_in_streaming;
        
        if (strlen(config->over_tls_server_domain)>0 || strlen(config->over_tls_path)>0) {
            tunnel->is_ws_protocol=true; //SSR-ws暂不支持，need.update
        }
//ssr类型的tls和ws并没有调试成功，need.update
    }

    cstl_set_container_add(ctx->env->tunnel_set, tunnel);
    ctx->parser = s5_ctx_create();
    ctx->cipher = NULL;
    ctx->stage = tunnel_stage_handshake;
    ctx->first_client_pkg = buffer_create(SSR_BUFF_SIZE);

#define SOCKET_DATA_BUFFER_SIZE 0x8000  //32768
    ctx->server_delivery_cache = buffer_create(SOCKET_DATA_BUFFER_SIZE);
    ctx->local_write_cache = buffer_create(SOCKET_DATA_BUFFER_SIZE);

    return true;
}

struct tunnel_ctx* client_tunnel_initialize(uv_tcp_t* lx, unsigned int idle_timeout) {
    uv_loop_t* loop = lx->loop;
    struct server_env_t* env = (struct server_env_t*)loop->data;

    return tunnel_initialize(loop, lx, idle_timeout, &init_done_cb, env);
}

static void client_tunnel_connecting_print_info(struct tunnel_ctx* tunnel) {
    struct client_ctx* ctx = (struct client_ctx*)tunnel->data;
    char* tmp = socks5_address_to_string(tunnel->desired_addr, &malloc, true);//eg:tmp="www.voachinese.com:443"
    const char* udp = ctx->udp_data_ctx ? "[UDP]" : "";
#if defined(__PRINT_INFO__)
    pr_info("++++ connecting %s \"%s\" ... ++++", udp, tmp);
#endif
    free(tmp);
    (void)udp;
}

static void client_tunnel_shutdown_print_info(struct tunnel_ctx* tunnel, bool success) {
    struct client_ctx* ctx = (struct client_ctx*)tunnel->data;
    char* tmp = socks5_address_to_string(tunnel->desired_addr, &malloc, true);
    const char* udp = (ctx->stage == tunnel_stage_s5_udp_accoc || ctx->udp_data_ctx) ? "[UDP]" : "";
    if (!success) {
#if defined(__PRINT_INFO__)
        pr_err("---- disconnected %s \"%s\" with failed. ---", udp, tmp);
#endif
    } else {
        if (udp && tunnel->desired_addr->port == 0) {
            // It's UDP ASSOCIATE requests, don't inform the closing status.
        } else {
#if defined(__PRINT_INFO__)
            pr_info("---- disconnected %s \"%s\" ----", udp, tmp);
#endif
        }
    }
    free(tmp);
}

static void tls_cli_on_shutting_down_callback(struct tls_cli_ctx* cli_ctx, void* p) {
    struct client_ctx* ctx = (struct client_ctx*)p;
    struct tunnel_ctx* tunnel = (struct tunnel_ctx*)ctx->tunnel;
    assert(tunnel);
    assert(ctx->tls_ctx == cli_ctx);
    client_tunnel_shutdown_print_info(tunnel, (ctx->connection_status == 0));
    client_ctx_release(ctx);
    tunnel_ctx_release(tunnel);

    (void)cli_ctx;
}

static void client_tunnel_shutdown(struct tunnel_ctx* tunnel) {
    struct client_ctx* ctx = (struct client_ctx*)tunnel->data;
    assert(ctx);
    if (ctx->tls_ctx) {
        client_ctx_add_ref(ctx);
        tls_client_shutdown(ctx->tls_ctx, tls_cli_on_shutting_down_callback, ctx);
    } else {
        client_tunnel_shutdown_print_info(tunnel, true);
    }
    assert(ctx && ctx->original_tunnel_shutdown);
    if (ctx && ctx->original_tunnel_shutdown) {
        ctx->original_tunnel_shutdown(tunnel);
    }
    if (tunnel->outbound) {
        hl_session_outbound_free(tunnel->outbound);
    }

   totovpn_free_obfs(tunnel);

}

static void tunnel_shutdown(struct tunnel_ctx* tunnel) {
    struct client_ctx* ctx = (struct client_ctx*)tunnel->data;
    assert(ctx);
    if (ctx->is_terminated == false) {
        ctx->is_terminated = true;
        client_tunnel_shutdown(tunnel);
    }
}

static bool tunnel_is_terminated(struct tunnel_ctx* tunnel) {
    struct client_ctx* ctx = (struct client_ctx*)tunnel->data;
    assert(ctx && (ctx->is_terminated == false || ctx->is_terminated == true));
    return (ctx->is_terminated != false);
}

static void _iterator_tunnel_shutdown(struct cstl_set* set, const void* obj, cstl_bool* stop, void* p) {
    struct tunnel_ctx* tunnel = (struct tunnel_ctx*)obj;
    tunnel->tunnel_shutdown(tunnel);
    (void)set; (void)stop; (void)p;
}

void client_env_shutdown(struct server_env_t* env) {
    cstl_set_container_traverse(env->tunnel_set, &_iterator_tunnel_shutdown, NULL);
}

static struct buffer_t* initial_package_create(const struct s5_ctx* parser) {
    size_t s = 0;
    uint8_t* b = s5_address_package_create(parser, &malloc, &s);
    struct buffer_t* buffer = buffer_create_from(b, s);
    free(b);
    return buffer;
}

/* This is the core state machine that drives the client <-> upstream proxy.
* We move through the initial handshake and authentication steps first and
* end up (if all goes well) in the proxy state where we're just proxying
* data between the client and upstream.
*/
static void tunnel_ssr_dispatcher(struct tunnel_ctx* tunnel, struct socket_ctx* socket) {
    struct client_ctx* ctx = (struct client_ctx*)tunnel->data;
//    struct server_env_t* env = ctx->env;
//    struct server_config* config = env->config;
    struct socket_ctx* incoming = tunnel->incoming;//连接到ssLocal的用户socket信息
    struct socket_ctx* outgoing = tunnel->outgoing;//ssLocal连接到ssServer的socket信息
    const char* info = tunnel_stage_string(ctx->stage); (void)info;
#if defined(__PRINT_INFO__)
    if (tunnel_ssr_is_in_streaming(tunnel)) {
        if (tunnel->in_streaming == false) {
            tunnel->in_streaming = true;
            pr_info("%s ...", info);
        }
    } else {
        pr_info("%s", info);
    }
#endif
    strncpy(tunnel->extra_info, info, 0x100 - 1);
//    ASSERT(config->over_tls_enable == false);
    switch (ctx->stage) {
    case tunnel_stage_handshake://收到客户端握手请求
        ASSERT(incoming->rdstate == socket_state_done);
        incoming->rdstate = socket_state_stop;
        do_handshake(tunnel);//响应客户端的握手信号
        break;
    case tunnel_stage_handshake_replied:
        ASSERT(incoming->wrstate == socket_state_done);
        incoming->wrstate = socket_state_stop;
        do_wait_client_app_s5_request(tunnel);
//  与客户端握手成功，则读取客户端接下来的请求建立连接的请求，下一步tunnel_stage_s5_request_from_client_app
        break;
    case tunnel_stage_s5_request_from_client_app: // client_socks5_request
        ASSERT(incoming->rdstate == socket_state_done);
        incoming->rdstate = socket_state_stop;
        do_parse_s5_request_from_client_app(tunnel,0);
// 客户端发来0x05 01(cmd) 00 03 targetAddr targePort，请求建立连接，如果是Tcp连接请求，则s5_connect_response_package返回0x05 00 00 01 addr port
// 语法分析客户端的request，
// 如走udp传输，则s5_build_udp_assoc_package创建updpakage， 下一个状态为tunnel_stage_s5_udp_accoc，
// 走tcp则do_socks5_reply_success回复建立socks_5连接成功， 下一状态为tunnel_stage_s5_response_done
        break;
    case tunnel_stage_s5_udp_accoc:
        ASSERT(incoming->wrstate == socket_state_done);
        incoming->wrstate = socket_state_stop;
        tunnel->tunnel_shutdown(tunnel);
        break;
    case tunnel_stage_s5_response_done: //
        ASSERT(incoming->wrstate == socket_state_done);
        incoming->wrstate = socket_state_stop;
//        printf("[ssClient] 响应认证后读取httpProxy首包数据\n");
        socket_ctx_read(incoming, true);
        ctx->stage = tunnel_stage_client_first_pkg; //连接成功后，读取请求数据,即为首个数据包
        break;
//-------------------------以上为shadowsocksProxy对client处理
            
//-------------------------以下为shadowsocksProxy对ssServer处理
    case tunnel_stage_client_first_pkg:
        ASSERT(incoming->rdstate == socket_state_done);
        incoming->rdstate = socket_state_stop;
        do_common_connet_remote_server(tunnel);  //取得client发来的首个数据包，则开始向ssr节点请求建立连接
//   ssr节点host未解析，则socket_ctx_getaddrinfo进行DNS解析处理,下一步为解析完成状态>tunnel_stage_resolve_ssr_server_host_done,
//   连接ssr成功则>tunnel_stage_connect_ssr_server_done
        break;
    case tunnel_stage_resolve_ssr_server_host_done: //DNS解析完成
        do_resolve_ssr_server_host_aftercare(tunnel); //再次do_connect_ssr_server发起连接，连接成功则下一步>tunnel_stage_connect_ssr_server_done
        break;
    case tunnel_stage_connect_ssr_server_done://连接成功，则发起认证请求
        do_ssr_send_auth_package_to_server(tunnel);
//向ssr节点发送认证，发送完毕则下一步>tunnel_stage_ssr_auth_sent，等待服务确认
        break;
    case tunnel_stage_ssr_auth_sent: //已发送认证请求，则等待服务确认
        ASSERT(outgoing->wrstate == socket_state_done);
        outgoing->wrstate = socket_state_stop;
        do_ssr_waiting_server_feedback(tunnel);
//   等待ssr认证回应：
//   如果需要等待ssr回应，则下一步开始读取ssr节点发来的回应消息，并在下一步判断是否需向服务器回已应收到认证信息，
//   需要回应则下一步tunnel_stage_ssr_server_feedback_arrived
//   如果不需要ssr回应确认，则直接表明认证成功tunnel_stage_auth_completion_done
        break;
    case tunnel_stage_ssr_server_feedback_arrived: //SSR会出现反馈收不到的情况
        ASSERT(outgoing->rdstate == socket_state_done);
        outgoing->rdstate = socket_state_stop;
        if (do_ssr_receipt_for_feedback(tunnel) == false) {
//ssr回应认证成功，并且不需回复确认收到认证成功，则下一步表明认证完成>tunnel_stage_auth_completion_done
            do_action_after_auth_server_success(tunnel);
        }else{
//   否则会在do_ssr_receipt_for_feedback里回复ssr我们到到了认证成功的回应，
//   接着下一步>tunnel_stage_ssr_receipt_to_server_sent
     }

        break;
    case tunnel_stage_ssr_receipt_to_server_sent:
        ASSERT(outgoing->wrstate == socket_state_done);
        outgoing->wrstate = socket_state_stop;
        do_action_after_auth_server_success(tunnel);//已回复ssr我们收到认证成功的消息，则表明认证完成
        break;
    case tunnel_stage_auth_completion_done: //认证成功，开始数据传输
        ASSERT(incoming->rdstate == socket_state_stop);
        ASSERT(incoming->wrstate == socket_state_stop);
        ASSERT(outgoing->rdstate == socket_state_stop);
        ASSERT(outgoing->wrstate == socket_state_stop);
        do_launch_streaming(tunnel);
        break;
    case tunnel_stage_streaming:
        tunnel_ssr_client_streaming(tunnel, socket);
//通过tunnel_extract_data加密/解密传输数据，然后转发给ssrServer 或 httpProxy客户端
        break;
    case tunnel_stage_kill:
        tunnel->tunnel_shutdown(tunnel);
        break;
    default:
        UNREACHABLE();
    }
}

/*
 实际为tls+ws，即wss协议，但实测tls却不成功
 */
//static void tunnel_tls_dispatcher(struct tunnel_ctx* tunnel, struct socket_ctx* socket) {
//    struct client_ctx* ctx = (struct client_ctx*)tunnel->data;
//    struct server_env_t* env = ctx->env;
////    struct server_config* config = env->config;
//    struct socket_ctx* incoming = tunnel->incoming;
//    const char* info = tunnel_stage_string(ctx->stage); (void)info;
//#if defined(__PRINT_INFO__)
//    if (tunnel_tls_is_in_streaming(tunnel)) {
//        if (tunnel->in_streaming == false) {
//            tunnel->in_streaming = true;
//            pr_info("%s ...", info);
//        }
//    } else {
//        pr_info("%s", info);
//    }
//#endif
//    strncpy(tunnel->extra_info, info, 0x100 - 1);
//
////    ASSERT(config->over_tls_enable);
//    switch (ctx->stage) {
//    case tunnel_stage_handshake:
//        ASSERT(incoming->rdstate == socket_state_done);
//        incoming->rdstate = socket_state_stop;
//        do_handshake(tunnel);
//        break;
//    case tunnel_stage_handshake_replied:
//        ASSERT(incoming->wrstate == socket_state_done);
//        incoming->wrstate = socket_state_stop;
//        do_wait_client_app_s5_request(tunnel);
//        break;
//    case tunnel_stage_s5_request_from_client_app:
//        ASSERT(incoming->rdstate == socket_state_done);
//        incoming->rdstate = socket_state_stop;
//        do_parse_s5_request_from_client_app(tunnel,0);//认证请求回复确认
//        break;
//    case tunnel_stage_s5_udp_accoc:
//        ASSERT(incoming->wrstate == socket_state_done);
//        incoming->wrstate = socket_state_stop;
//        tunnel->tunnel_shutdown(tunnel);
//        break;
//    case tunnel_stage_s5_response_done:
//        ASSERT(incoming->wrstate == socket_state_done);
//        incoming->wrstate = socket_state_stop;
////        printf("[ssClient] 响应s5认证后读取httpProxy首包数据\n");
//        socket_ctx_read(incoming, true);
//        ctx->stage = tunnel_stage_client_first_pkg;
//        break;
//    case tunnel_stage_client_first_pkg:
//        ASSERT(incoming->rdstate == socket_state_done);
//        incoming->rdstate = socket_state_stop;
//        do_common_connet_remote_server(tunnel);
//        break;
//    case tunnel_stage_auth_completion_done:
//        ASSERT(incoming->rdstate == socket_state_stop);
//        ASSERT(incoming->wrstate == socket_state_stop);
//        tunnel_tls_do_launch_streaming(tunnel); //发送tls_首包
//        break;
//    case tunnel_stage_tls_streaming:
//        tunnel_tls_client_incoming_streaming(tunnel, socket);
//        break;
//    case tunnel_stage_kill:
//        tunnel->tunnel_shutdown(tunnel);
//        break;
//    default:
//        UNREACHABLE();
//    }
//}

static void do_handshake(struct tunnel_ctx* tunnel) {
    enum s5_auth_method methods;
    struct socket_ctx* incoming = tunnel->incoming;
    struct client_ctx* ctx = (struct client_ctx*)tunnel->data;
    struct s5_ctx* parser = ctx->parser;
    uint8_t* data;
    size_t size;
    enum s5_result result;

    ASSERT(incoming->rdstate == socket_state_stop);
    ASSERT(incoming->wrstate == socket_state_stop);

    if (incoming->result < 0) {
        char buff[256] = { 0 };
        pr_err("read error: %s", uv_strerror_r((int)incoming->result, buff, sizeof(buff)));
        tunnel->tunnel_shutdown(tunnel);
        return;
    }

    data = (uint8_t*)incoming->buf->base;
    size = (size_t)incoming->result;
    result = s5_parse(parser, &data, &size);
    if (result == s5_result_need_more) {
        /* Need more data. but we do NOT handle this situation */
        tunnel->tunnel_shutdown(tunnel);
        return;
    }

    if (size != 0) {
        /* Could allow a round-trip saving shortcut here if the requested auth
        * method is s5_auth_none (provided unauthenticated traffic is allowed.)
        * Requires client support however.
        */
        pr_err("junk in handshake");
        tunnel->tunnel_shutdown(tunnel);
        return;
    }

    if (result != s5_result_auth_select) {
        pr_err("handshake error: %s", str_s5_result(result));
        tunnel->tunnel_shutdown(tunnel);
        return;
    }

    methods = s5_get_auth_methods(parser);
    if ((methods & s5_auth_none) && can_auth_none(tunnel)) {
        s5_select_auth(parser, s5_auth_none);
        tunnel_socket_ctx_write(tunnel, incoming, "\5\0", 2); /* No auth required. */
        ctx->stage = tunnel_stage_handshake_replied; //已回应握手
        return;
    }

    if ((methods & s5_auth_passwd) && can_auth_passwd(tunnel)) {
        tunnel->tunnel_shutdown(tunnel);
        return;
    }

    tunnel_socket_ctx_write(tunnel, incoming, "\5\377", 2); /* No acceptable auth. */
    ctx->stage = tunnel_stage_kill;
}

static void do_wait_client_app_s5_request(struct tunnel_ctx* tunnel) {
    struct client_ctx* ctx = (struct client_ctx*)tunnel->data;
    struct socket_ctx* incoming = tunnel->incoming;

    ASSERT(incoming->rdstate == socket_state_stop);
    ASSERT(incoming->wrstate == socket_state_stop);

    if (incoming->result < 0) {
        char buff[256] = { 0 };
        pr_err("write error: %s", uv_strerror_r((int)incoming->result, buff, sizeof(buff)));
        tunnel->tunnel_shutdown(tunnel);
        return;
    }
    socket_ctx_read(incoming, true);
    ctx->stage = tunnel_stage_s5_request_from_client_app;
}

/*
    处理收到的socks5认证请求
 */
static void do_parse_s5_request_from_client_app(struct tunnel_ctx* tunnel,int proxyType) {
    struct socket_ctx* incoming = tunnel->incoming;
    struct socket_ctx* outgoing = tunnel->outgoing;
    struct client_ctx* ctx = (struct client_ctx*)tunnel->data;
    struct s5_ctx* parser = ctx->parser;
    uint8_t* data;
    size_t size;
    enum s5_result result;
    struct server_env_t* env = ctx->env;
    struct server_config* config = env->config;
    
    
    ASSERT(incoming->rdstate == socket_state_stop);
    ASSERT(incoming->wrstate == socket_state_stop);
    ASSERT(outgoing->rdstate == socket_state_stop);
    ASSERT(outgoing->wrstate == socket_state_stop);

    if (incoming->result < 0) {
        char buff[256] = { 0 };
        pr_err("read error: %s", uv_strerror_r((int)incoming->result, buff, sizeof(buff)));
        tunnel->tunnel_shutdown(tunnel);
        return;
    }

    data = (uint8_t*)incoming->buf->base;
    size = (size_t)incoming->result;
    
// 解析出目标域名或地址，及目标Port，存入tunnel->desired_addr
    socks5_address_parse(data + 3, size - 3, tunnel->desired_addr);//从ATYP字段截取认证数据,根据type取得destAddr及destProt
    result = s5_parse(parser, &data, &size);//将socks5数据进一步解析到parser，亦即解析到ctx->parser中,(会改变data)
    if (result == s5_result_need_more) {
        pr_err("%s", "More data is needed, but we are not going to continue.");
        tunnel->tunnel_shutdown(tunnel);
        return;
    }

    if (size != 0) {
        pr_err("junk in request %u", (unsigned)size);
        tunnel->tunnel_shutdown(tunnel);
        return;
    }

    if (result != s5_result_exec_cmd) {
        pr_err("request error: %s", str_s5_result(result));
        tunnel->tunnel_shutdown(tunnel);
        return;
    }
//此时httpProxy发过来的是协商建立连接的请求：0x05 01(cmd) 00 03 targetAddr targePort
// cmd=01表示tcp连接，02=bind, 03表示upd连接，
    switch (s5_get_cmd(parser)) {
    case s5_cmd_tcp_bind:
        /* Not supported but relatively straightforward to implement. */
        pr_warn("BIND requests are not supported.");
        tunnel->tunnel_shutdown(tunnel);
        break;
    case s5_cmd_udp_assoc: {
        // UDP ASSOCIATE requests
        size_t len = 0;
        uint8_t* buf;

        union sockaddr_universal sockname;
        int namelen = sizeof(sockname);
        char* addr;
        uint16_t port = 0;

        VERIFY(0 == uv_tcp_getsockname(&incoming->handle.tcp, (struct sockaddr*)&sockname, &namelen));

        addr = universal_address_to_string(&sockname, &malloc, false);
        port = universal_address_get_port(&sockname);

        buf = s5_build_udp_assoc_package(config->udp, addr, port, &malloc, &len);
        free(addr);
        
        tunnel_socket_ctx_write(tunnel, incoming, buf, len);
        free(buf);
        
        ctx->stage = tunnel_stage_s5_udp_accoc;
        
    } break;
    case s5_cmd_tcp_connect:
        if (tunnel->desired_addr->addr.ipv4.s_addr == 0 && tunnel->desired_addr->addr_type == SOCKS5_ADDRTYPE_IPV4) {
            pr_err("%s", "zero target address, dropped.");
            tunnel->tunnel_shutdown(tunnel);
            return;
        }
//proxyType=1 shadowsocks,2=vmess
        if (1==proxyType){
           totovpn_init_outbound(tunnel, (uint8_t*)incoming->buf->base,incoming->buf->len);
        }
        else if (2==proxyType) {
            vmess_init_outbound(tunnel,(uint8_t*)incoming->buf->base,incoming->buf->len);
        }
            
        do_socks5_reply_success(tunnel);
        break;
    default:
        UNREACHABLE();
        break;
    }
}

static void _do_protect_socket(struct tunnel_ctx* tunnel, uv_os_sock_t fd) {
#if ANDROID
    if (protect_socket(fd) == -1) {
        LOGE("protect_socket");
        tunnel->tunnel_shutdown(tunnel);
        return;
    }
#endif
    (void)tunnel; (void)fd;
}

/*
 ssl/tls 连接中回调，android下有用
 */
static void _tls_cli_tcp_conn_cb(struct tls_cli_ctx* cli, void* p) {
    struct client_ctx* ctx = (struct client_ctx*)p;
    struct tunnel_ctx* tunnel = ctx->tunnel;
    _do_protect_socket(tunnel, tls_client_get_tcp_fd(cli));
}

static struct tls_cli_ctx* tls_client_creator(struct client_ctx* ctx, struct server_config* config) {
    struct tunnel_ctx* tunnel = ctx->tunnel;
    if (strlen(config->over_tls_server_domain)==0) {
        strcpy(config->over_tls_server_domain, config->remote_host);
    }
    struct tls_cli_ctx* tls_cli = tls_client_launch(tunnel->loop, config->over_tls_server_domain,
        config->remote_host, config->remote_port, config->connect_timeout_ms);
    if (tls_cli) { //tls_cli->mbd->
        tls_client_set_tcp_connect_callback(tls_cli, _tls_cli_tcp_conn_cb, ctx);
        tls_cli_set_on_connection_established_callback(tls_cli, tls_cli_on_connection_established, ctx);
        tls_cli_set_on_write_done_callback(tls_cli, tls_cli_on_write_done, ctx);
        tls_cli_set_on_data_received_callback(tls_cli, tls_cli_on_data_received, ctx);
        tunnel_ctx_add_ref(tunnel);
    }

    return tls_cli;
}

/*
    收到第1个数据包时，开始进行服务节点的连接
 */
static void do_common_connet_remote_server(struct tunnel_ctx* tunnel) {
    struct socket_ctx* incoming = tunnel->incoming;
    struct socket_ctx* outgoing = tunnel->outgoing;
    struct client_ctx* ctx = (struct client_ctx*)tunnel->data;
    struct s5_ctx* parser = ctx->parser;//parser为认证请求信息：包含destAddr、destPort
    struct server_env_t* env = ctx->env;

    struct server_config* config = env->config;
    uint8_t* data = (uint8_t*)incoming->buf->base; //读取socket得到的数据存在buf中
    size_t size = (size_t)incoming->result;

    buffer_store(ctx->first_client_pkg, data, size); //将incoming接收到的缓存数据buf，存到first_client_pkg中当作首个包数据
    
    ctx->init_pkg = initial_package_create(parser);//将认证信息(包含destAddr、destPort)存到init_pkg
    
    ctx->cipher = tunnel_cipher_create(ctx->env, 1452); //ssr节点信息，生成加密数据cipher

    if(0==strcasecmp(config->proxytype, "ssr"))
    {// 没搞懂这一块作用是？info赋值后，并没有使用，只为server_info_t设置buffer_size和head_len？
        struct obfs_t* protocol = ctx->cipher->protocol;
        struct obfs_t* obfs = ctx->cipher->obfs;
        struct server_info_t* info;
        info = protocol ? protocol->get_server_info(protocol) : (obfs ? obfs->get_server_info(obfs) : NULL);
        if (info) {
            size_t s0 = buffer_get_length(ctx->init_pkg);
            const uint8_t* p0 = buffer_get_data(ctx->init_pkg);
            info->buffer_size = SSR_BUFF_SIZE;
            info->head_len = (int)get_s5_head_size(p0, s0, 30);
        }
    }

    client_tunnel_connecting_print_info(tunnel);

//    if (config->over_tls_enable) {
//        ctx->stage = tunnel_stage_tls_connecting;
//        if (strcasecmp(config->proxytype, "ss")==0) {
//            strcpy(config->over_tls_server_domain, config->obfs_param);
//        }
//        ctx->tls_ctx = tls_client_creator(ctx, config);
//        if (ctx->tls_ctx == NULL) {
//            outgoing->result = UV_ENETUNREACH;
//            tunnel_dump_error_info(tunnel, outgoing, "connect failed");
//            tunnel->tunnel_shutdown(tunnel);
//        }
//        return;
//    }
//    else
    {
        union sockaddr_universal remote_addr = { { 0 } };
        if (universal_address_from_string_no_dns(config->remote_host, config->remote_port, &remote_addr) != 0) {
//若ssr节点remote_host为域名，则进一步DNS解析
//printf("服务节点(%s:%d)需先进行DNS解析\n",config->remote_host,config->remote_port);
            socket_ctx_getaddrinfo(outgoing, config->remote_host, config->remote_port);
            ctx->stage = tunnel_stage_resolve_ssr_server_host_done; //下一步为DNS解析完成状态
            return;
        }
        outgoing->addr = remote_addr;
        do_connect_ssr_server(tunnel);
    }
}

/*
 DNS解析完成，继续向服务节点发起连接
 */
static void do_resolve_ssr_server_host_aftercare(struct tunnel_ctx* tunnel) {
    struct socket_ctx* incoming = tunnel->incoming;
    struct socket_ctx* outgoing = tunnel->outgoing;
    struct client_ctx* ctx = (struct client_ctx*)tunnel->data;
    struct server_env_t* env = ctx->env;
    struct server_config* config = env->config;

    ASSERT(incoming->rdstate == socket_state_stop);
    ASSERT(incoming->wrstate == socket_state_stop);
    ASSERT(outgoing->rdstate == socket_state_stop);
    ASSERT(outgoing->wrstate == socket_state_stop);

    if (outgoing->result < 0) {
        char buff[256] = { 0 };
        /* TODO Escape control characters in parser->daddr. */
        pr_err("lookup error for \"%s\": %s", config->remote_host,
            uv_strerror_r((int)outgoing->result, buff, sizeof(buff)));
        /* Send back a 'Host unreachable' reply. */
        tunnel_socket_ctx_write(tunnel, incoming, "\5\4\0\1\0\0\0\0\0\0", 10);
        ctx->stage = tunnel_stage_kill;
        return;
    }

    /* Don't make assumptions about the offset of sin_port/sin6_port. */
    switch (outgoing->addr.addr.sa_family) {
    case AF_INET:
        outgoing->addr.addr4.sin_port = htons(config->remote_port);
        break;
    case AF_INET6:
        outgoing->addr.addr6.sin6_port = htons(config->remote_port);
        break;
    default:
        UNREACHABLE();
    }
    
//    printf("[ssClient] DNS解析完毕请求连接ssServer(%s:%d)\n",config->remote_host,config->remote_port);
    do_connect_ssr_server(tunnel);
}

/* Assumes that cx->outgoing.t.sa contains a valid AF_INET/AF_INET6 address. */
static void do_connect_ssr_server(struct tunnel_ctx* tunnel) {
    struct client_ctx* ctx = (struct client_ctx*)tunnel->data;
    struct server_config* config = ctx->env->config;
    struct socket_ctx* incoming = tunnel->incoming;
    struct socket_ctx* outgoing = tunnel->outgoing;
    int err;

    (void)config;
    ASSERT(incoming->rdstate == socket_state_stop);
    ASSERT(incoming->wrstate == socket_state_stop);
    ASSERT(outgoing->rdstate == socket_state_stop);
    ASSERT(outgoing->wrstate == socket_state_stop);

    if (!can_access(tunnel, &outgoing->addr.addr)) {
        pr_warn("connection not allowed by ruleset");
        /* Send a 'Connection not allowed by ruleset' reply. */
        tunnel_socket_ctx_write(tunnel, incoming, "\5\2\0\1\0\0\0\0\0\0", 10);
        ctx->stage = tunnel_stage_kill;
        return;
    }
//正式向ssr节点服务发起连接,
    err = socket_ctx_connect(outgoing);
    if (err != 0) {
        char buff[256] = { 0 };
        pr_err("connect error: %s", uv_strerror_r(err, buff, sizeof(buff)));
        tunnel->tunnel_shutdown(tunnel);
        return;
    }

    ctx->stage = tunnel_stage_connect_ssr_server_done;
}

//连接服务节点成功后，发送握手认证
static void do_ssr_send_auth_package_to_server(struct tunnel_ctx* tunnel) {
    struct socket_ctx* incoming = tunnel->incoming;
    struct socket_ctx* outgoing = tunnel->outgoing;
    struct client_ctx* ctx = (struct client_ctx*)tunnel->data;

    ASSERT(incoming->rdstate == socket_state_stop);
    ASSERT(incoming->wrstate == socket_state_stop);
    ASSERT(outgoing->rdstate == socket_state_stop);
    ASSERT(outgoing->wrstate == socket_state_stop);

    if (outgoing->result == 0) {
        {
            const uint8_t* out_data = NULL; size_t out_data_len = 0;
            struct buffer_t* tmp = buffer_create(SSR_BUFF_SIZE);
            buffer_replace(tmp, ctx->init_pkg);//init_pkg为请求的目标地址及port信息
//加密、混淆shadowsocks-header
            if (ssr_ok != tunnel_cipher_client_encrypt(ctx->cipher, tmp)) {
                buffer_release(tmp);
                tunnel->tunnel_shutdown(tunnel);
                return;
            }
            
            _do_protect_socket(tunnel, uv_stream_fd(&outgoing->handle.tcp)); //android才需要

            out_data = buffer_get_data(tmp);
            out_data_len = buffer_get_length(tmp);
//发送shadowsocks-header，进行shadowsocks握手认证
            tunnel_socket_ctx_write(tunnel, outgoing, out_data, out_data_len);
            buffer_release(tmp);
            
            ctx->stage = tunnel_stage_ssr_auth_sent;
        }
        return;
        
        
    } else {// outgoing->result == 0
        tunnel_dump_error_info(tunnel, outgoing, "upstream connection");
        /* Send a 'Connection refused' reply. */
        tunnel_socket_ctx_write(tunnel, incoming, "\5\5\0\1\0\0\0\0\0\0", 10);
        ctx->stage = tunnel_stage_kill;
        return;
    }

    UNREACHABLE();
    tunnel->tunnel_shutdown(tunnel);
}

static void do_ssr_waiting_server_feedback(struct tunnel_ctx* tunnel) {
    struct socket_ctx* incoming = tunnel->incoming;
    struct socket_ctx* outgoing = tunnel->outgoing;
    struct client_ctx* ctx = (struct client_ctx*)tunnel->data;

    ASSERT(incoming->rdstate == socket_state_stop);
    ASSERT(incoming->wrstate == socket_state_stop);
    ASSERT(outgoing->rdstate == socket_state_stop);
    ASSERT(outgoing->wrstate == socket_state_stop);

    if (outgoing->result < 0) {
        char buff[256] = { 0 };
        pr_err("write error: %s", uv_strerror_r((int)outgoing->result, buff, sizeof(buff)));
        tunnel->tunnel_shutdown(tunnel);
        return;
    }
    
    if (tunnel_cipher_client_need_feedback(ctx->cipher)) {
//printf("[ssClient] 发送认证请求后需要反馈>读取ssServer响应\n");
        socket_ctx_read(outgoing, true);
        ctx->stage = tunnel_stage_ssr_server_feedback_arrived;
    } else {
        do_action_after_auth_server_success(tunnel);
    }
}

/*
 校验ws是否成功，不成功返回true
 */
static bool vmess_ws_upgrade_check(const char *data)
{
    return strncmp(data, ws_upgrade, strlen(ws_upgrade)) != 0 || !strstr(data, ws_accept);
}

static bool do_ssr_receipt_for_feedback(struct tunnel_ctx* tunnel) {
    struct socket_ctx* incoming = tunnel->incoming;
    struct socket_ctx* outgoing = tunnel->outgoing;
    struct client_ctx* ctx = (struct client_ctx*)tunnel->data;
    struct tunnel_cipher_ctx* cipher_ctx = ctx->cipher;
    enum ssr_error error = ssr_error_client_decode;
    struct buffer_t* buf = NULL;
    struct buffer_t* feedback = NULL;
    bool done = false;

    ASSERT(incoming->rdstate == socket_state_stop);
    ASSERT(incoming->wrstate == socket_state_stop);
    ASSERT(outgoing->rdstate == socket_state_stop);
    ASSERT(outgoing->wrstate == socket_state_stop);

    if (outgoing->result < 0) {
        char buff[256] = { 0 };
        pr_err("read error: %s", uv_strerror_r((int)outgoing->result, buff, sizeof(buff)));
        tunnel->tunnel_shutdown(tunnel);
        return done;
    }
// buf数据为:  "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Encoding: gzip\.."
    buf = buffer_create_from((uint8_t*)outgoing->buf->base, (size_t)outgoing->result);
    error = tunnel_cipher_client_decrypt(cipher_ctx, buf, &feedback);
//    printf("[ssClient] decrypt[ssServer]认证响应\n");
    ASSERT(error == ssr_ok);
    ASSERT(buffer_get_length(buf) == 0);

    if (feedback) {
//        printf("[ssClient] 反馈收到认证请求响应->ssServer\n");
        tunnel_socket_ctx_write(tunnel, outgoing, buffer_get_data(feedback), buffer_get_length(feedback));
        ctx->stage = tunnel_stage_ssr_receipt_to_server_sent;
        buffer_release(feedback);
        done = true;
    }

    buffer_release(buf);
    return done;
}

static void do_socks5_reply_success(struct tunnel_ctx* tunnel) {
    struct client_ctx* ctx = (struct client_ctx*)tunnel->data;
    struct socket_ctx* incoming = tunnel->incoming;
    struct socket_ctx* outgoing = tunnel->outgoing;
    uint8_t* buf;
    size_t size = 0;
//返回建立连接请求响应：0x05 00 00 01 addr port
    buf = s5_connect_response_package(ctx->parser, &malloc, &size);

    ASSERT(incoming->rdstate == socket_state_stop);
    ASSERT(incoming->wrstate == socket_state_stop);
    ASSERT(outgoing->rdstate == socket_state_stop);
    ASSERT(outgoing->wrstate == socket_state_stop);
//    printf("[ssClient] 响应[httpProxy]连接请求<%d>\n",size);
    tunnel_socket_ctx_write(tunnel, incoming, buf, size);
    free(buf);
    ctx->stage = tunnel_stage_s5_response_done; //已返回认证请求
}

/*
  完成与服务端的连接认证
 */
static void do_action_after_auth_server_success(struct tunnel_ctx* tunnel) {
    struct socket_ctx* outgoing = tunnel->outgoing;
    struct client_ctx* ctx = (struct client_ctx*)tunnel->data;
    ctx->stage = tunnel_stage_auth_completion_done;
    tunnel->tunnel_dispatcher(tunnel, outgoing);
}

static void do_launch_streaming(struct tunnel_ctx* tunnel) {
    struct client_ctx* ctx = (struct client_ctx*)tunnel->data;
    struct socket_ctx* incoming = tunnel->incoming;
    struct socket_ctx* outgoing = tunnel->outgoing;

    ASSERT(incoming->rdstate == socket_state_stop);
    ASSERT(incoming->wrstate == socket_state_stop);
    ASSERT(outgoing->rdstate == socket_state_stop);
    ASSERT(outgoing->wrstate == socket_state_stop);

    if (incoming->result < 0) {
        char buff[256] = { 0 };
        pr_err("write error: %s", uv_strerror_r((int)incoming->result, buff, sizeof(buff)));
        tunnel->tunnel_shutdown(tunnel);
        return;
    }
    
    const uint8_t* out_data = NULL;
    size_t out_data_len = 0;
    struct buffer_t* tmp = buffer_create(SSR_BUFF_SIZE);
    buffer_replace(tmp, ctx->first_client_pkg);

    if (ssr_ok != tunnel_cipher_client_encrypt(ctx->cipher, tmp)) {//然后加密tmp
        buffer_release(tmp);
        tunnel->tunnel_shutdown(tunnel);
        return;
    }
    out_data = buffer_get_data(tmp); //out_data为加密后的数据
    out_data_len = buffer_get_length(tmp);
    tunnel_socket_ctx_write(tunnel, outgoing, out_data, out_data_len);
    buffer_release(tmp);
    buffer_reset(ctx->first_client_pkg, true);
    
//    printf("[ssClient] 发送首包后>继续读取httpProxy请求数据\n");
    socket_ctx_read(incoming, false); //接收httpRroxy转发来的数据
//    printf("[ssClient] 发送首包后>读取ssServer响应数据\n");
    socket_ctx_read(outgoing, true); //接收ssr服务转发来的数据
        
    ctx->stage = tunnel_stage_streaming;
}

static void tunnel_ssr_client_streaming(struct tunnel_ctx* tunnel, struct socket_ctx* socket) {
    struct socket_ctx* current_socket = socket;
    struct socket_ctx* target_socket = NULL;
    size_t len = 0;
    uint8_t* buf = NULL;
    
//    struct client_ctx* ctx = (struct client_ctx*)tunnel->data;
    ASSERT(socket->rdstate == socket_state_done || socket->wrstate == socket_state_done);
    
    if (socket->wrstate == socket_state_done) {
        socket->wrstate = socket_state_stop;
        return; // just return without doing anything.
    } else if (socket->rdstate == socket_state_done) {
        socket->rdstate = socket_state_stop;
    } else {
        UNREACHABLE();
    }

    ASSERT(current_socket == tunnel->incoming || current_socket == tunnel->outgoing);
    
    target_socket = ((current_socket == tunnel->incoming) ? tunnel->outgoing : tunnel->incoming);
//如果incoming发来的数据，则target_socket为为outgoing，反之
    ASSERT(tunnel->tunnel_extract_data);
    
    if (tunnel->tunnel_extract_data) {
        buf = tunnel->tunnel_extract_data(tunnel, current_socket, &malloc, &len);//得到加密/解密后的数据，再转发给server或local
    }

#if ANDROID
    if (log_tx_rx) {
        if (current_socket == tunnel->incoming) {
            tx += len;
        } else {
            rx += len;
        }
        stat_update_cb();
    }
#endif

    if (buf /* && len > 0 */) {
        tunnel_socket_ctx_write(tunnel, target_socket, buf, len);
    } else {
        tunnel->tunnel_shutdown(tunnel);
    }
    free(buf);
}

static uint8_t* tunnel_extract_data(struct tunnel_ctx* tunnel, struct socket_ctx* socket, void* (*allocator)(size_t size), size_t* size)
{
    struct client_ctx* ctx = (struct client_ctx*)tunnel->data;
//    struct server_config* config = ctx->env->config;
    struct tunnel_cipher_ctx* cipher_ctx = ctx->cipher;
    enum ssr_error error = ssr_error_client_decode;
    struct buffer_t* buf = NULL;
    uint8_t* result = NULL;

    if (socket == NULL || allocator == NULL || size == NULL) {
        return result;
    }
    *size = 0;
    buf = buffer_create(SSR_BUFF_SIZE); buffer_store(buf, (uint8_t*)socket->buf->base, (size_t)socket->result);

    if (socket == tunnel->incoming) {
//        printf("[ssClient] (encrypt)->ssServer\n"); //太多
        error = tunnel_cipher_client_encrypt(cipher_ctx, buf); //将客户端请求数据加密后转发给服务节点
    } else if (socket == tunnel->outgoing) {
        struct buffer_t* feedback = NULL;
//        ASSERT(config->over_tls_enable == false);
//        printf("[ssServer](decrypt)->ssClient\n");//太多
        error = tunnel_cipher_client_decrypt(cipher_ctx, buf, &feedback);//将服务节点响应数据解密后转发给客户端
        if (feedback) {
            ASSERT(false);
            buffer_release(feedback);
        }
    } else {
        ASSERT(false);
    }

    if (error == ssr_ok) {
        size_t len = buffer_get_length(buf);
        *size = len;
        result = (uint8_t*)allocator(len + 1);
        memcpy(result, buffer_get_data(buf), len);
        result[len] = 0;
    }

    buffer_release(buf);
    return result;
}


static void tunnel_destroying(struct tunnel_ctx* tunnel) {
    struct client_ctx* ctx = (struct client_ctx*)tunnel->data;
    cstl_set_container_remove(ctx->env->tunnel_set, tunnel);
    client_ctx_release(ctx);
}

void client_ctx_destroy_internal(struct client_ctx* ctx) {
    if (ctx->cipher) {
        tunnel_cipher_release(ctx->cipher);
    }
    buffer_release(ctx->init_pkg);
    buffer_release(ctx->first_client_pkg);
    s5_ctx_release(ctx->parser);
    object_safe_free((void**)&ctx->sec_websocket_key);
    buffer_release(ctx->server_delivery_cache);
    buffer_release(ctx->local_write_cache);
    udp_data_context_destroy(ctx->udp_data_ctx);
    tls_cli_ctx_release(ctx->tls_ctx);
    free(ctx);
}

REF_COUNT_ADD_REF_IMPL(client_ctx)
REF_COUNT_RELEASE_IMPL(client_ctx, client_ctx_destroy_internal)

static void tunnel_timeout_expire_done(struct tunnel_ctx* tunnel, struct socket_ctx* socket) {
    (void)tunnel;
    (void)socket;
}

static void tunnel_outgoing_connected_done(struct tunnel_ctx* tunnel, struct socket_ctx* socket) {
    tunnel->tunnel_dispatcher(tunnel, socket);
}

static void tunnel_read_done(struct tunnel_ctx* tunnel, struct socket_ctx* socket) {
    tunnel->tunnel_dispatcher(tunnel, socket);
}

static void tunnel_arrive_end_of_file(struct tunnel_ctx* tunnel, struct socket_ctx* socket) {
    (void)socket;
    tunnel->tunnel_shutdown(tunnel);
}

static void tunnel_on_getaddrinfo_done(struct tunnel_ctx* tunnel, struct socket_ctx* socket, const struct addrinfo* ai) {
    tunnel->tunnel_dispatcher(tunnel, socket);
    (void)ai;
}

static void tunnel_write_done(struct tunnel_ctx* tunnel, struct socket_ctx* socket) {
    tunnel->tunnel_dispatcher(tunnel, socket);
}

static size_t tunnel_get_alloc_size(struct tunnel_ctx* tunnel, struct socket_ctx* socket, size_t suggested_size) {
    (void)tunnel;
    (void)socket;
    (void)suggested_size;
    return SSR_BUFF_SIZE;
}

static bool tunnel_ssr_is_in_streaming(struct tunnel_ctx* tunnel) {
    struct client_ctx* ctx = (struct client_ctx*)tunnel->data;
    return (ctx && ctx->stage == tunnel_stage_streaming);
}

//static bool tunnel_tls_is_in_streaming(struct tunnel_ctx* tunnel) {
//    struct client_ctx* ctx = (struct client_ctx*)tunnel->data;
//    return (ctx && ctx->stage == tunnel_stage_tls_streaming);
//}

//static void tunnel_tls_do_launch_streaming(struct tunnel_ctx* tunnel) {
//    struct client_ctx* ctx = (struct client_ctx*)tunnel->data;
//    struct socket_ctx* incoming = tunnel->incoming;
//
//    ASSERT(incoming->rdstate == socket_state_stop);
//    ASSERT(incoming->wrstate == socket_state_stop);
//
//    if (incoming->result < 0) {
//        char buff[256] = { 0 };
//        PRINT_ERR("[TLS] write error: %s", uv_strerror_r((int)incoming->result, buff, sizeof(buff)));
//        tunnel->tunnel_shutdown(tunnel);
//    } else {
//        const uint8_t* out_data = NULL;
//        size_t out_data_len = 0;
//        struct buffer_t* tmp = buffer_create(SSR_BUFF_SIZE);
//        buffer_replace(tmp, ctx->first_client_pkg);
//        buffer_reset(ctx->first_client_pkg, true);
//
//        if (ssr_ok != tunnel_cipher_client_encrypt(ctx->cipher, tmp)) {
//            buffer_release(tmp);
//            tunnel->tunnel_shutdown(tunnel);
//            return;
//        }
//        out_data = buffer_get_data(tmp);
//        out_data_len = buffer_get_length(tmp);
//        tls_cli_send_websocket_data(ctx, out_data, out_data_len);
//
//        buffer_release(tmp);
//        socket_ctx_read(incoming, true);
//        ctx->stage = tunnel_stage_tls_streaming;
//    }
//}

static void tls_cli_send_websocket_data(struct client_ctx* ctx, const uint8_t* buf, size_t len) {
    ws_frame_info info = { WS_OPCODE_BINARY, true, true, 0, 0, 0 };
    uint8_t* frame;
    ws_frame_binary_alone(true, &info);
    frame = websocket_build_frame(&info, buf, len, &malloc);
    tls_client_send_data(ctx->tls_ctx, frame, info.frame_size);
    free(frame);
}

//void tunnel_tls_client_incoming_streaming(struct tunnel_ctx* tunnel, struct socket_ctx* socket) {
//    struct client_ctx* ctx = (struct client_ctx*)tunnel->data;
//    ASSERT(socket == tunnel->incoming); (void)ctx;
//
//    ASSERT(socket->wrstate == socket_state_done || socket->rdstate == socket_state_done);
//
//    if (socket->wrstate == socket_state_done) {
//        socket->wrstate = socket_state_stop;
//        return;
//    }
//    else if (socket->rdstate == socket_state_done) {
//        socket->rdstate = socket_state_stop;
//        {
//            size_t len = 0;
//            uint8_t* buf = NULL;
//            ASSERT(tunnel->tunnel_extract_data);
//            buf = tunnel->tunnel_extract_data(tunnel, socket, &malloc, &len);
//
//#if ANDROID
//            if (log_tx_rx) {
//                tx += len;
//            }
//            stat_update_cb();
//#endif
//            if (buf /* && size > 0 */) {
//                tls_cli_send_websocket_data(ctx, buf, len);
//            } else {
//                tunnel->tunnel_shutdown(tunnel);
//            }
//            free(buf);
//        }
//    }
//    else {
//        ASSERT(false);
//    }
//}

/*
   ssl/tls 建立连接完毕回调
 */
static void tls_cli_on_connection_established(struct tls_cli_ctx* tls_cli, int status, void* p) {
    struct client_ctx* ctx = (struct client_ctx*)p;
    struct tunnel_ctx* tunnel = ctx->tunnel;

    struct socket_ctx* incoming = tunnel->incoming;
    struct socket_ctx* outgoing = tunnel->outgoing;
    struct server_config* config = ctx->env->config;

    assert(ctx->tls_ctx == tls_cli);

    ctx->connection_status = status;

    if (status < 0) {
        char* tmp = socks5_address_to_string(tunnel->desired_addr, &malloc, true);
        char buff[256] = { 0 };
        pr_err("[TLS] connecting \"%s\" failed: %d: %s", tmp, status, uv_strerror_r(status, buff, sizeof(buff)));
        free(tmp);

        tunnel->tunnel_shutdown(tunnel);
        return;
    }

    if (tunnel->tunnel_is_terminated(tunnel)) {
        return;
    }
    
    char* tmpLog = socks5_address_to_string(tunnel->desired_addr, &malloc, true);
    printf("[ssClient] [TLS] connecting %s success!\n",tmpLog);
    free(tmpLog);

    ASSERT(incoming->rdstate == socket_state_stop);
    ASSERT(incoming->wrstate == socket_state_stop);
    ASSERT(outgoing->rdstate == socket_state_stop);
    ASSERT(outgoing->wrstate == socket_state_stop);

    if (strcasecmp(config->proxytype, "ss")){
//  ----------ss
//        totovpn_send_ss_header(ctx,true);
        return;
    }
    else if (strcasecmp(config->proxytype, "vmess")){
//----------vmess
        
    }
    
    
    {
// --------------------------ss-tls-begin
        struct buffer_t* tmp = buffer_create(SSR_BUFF_SIZE);
        buffer_replace(tmp, ctx->init_pkg);//发送目标地址及端口等信息

            if (ctx->udp_data_ctx) {
                const void* udp_pkg = cstl_deque_front(ctx->udp_data_ctx->send_deque);
                if (udp_pkg) {
                    buffer_replace(tmp, *((const struct buffer_t**)udp_pkg));
                    cstl_deque_pop_front(ctx->udp_data_ctx->send_deque);
                }
            }

            {
                const char* url_path = config->over_tls_path;
                const char* domain = config->over_tls_server_domain;
                unsigned short domain_port = config->remote_port;
                uint8_t* buf = NULL;
                size_t len = 0;
                size_t typ_len = buffer_get_length(tmp);
                const uint8_t* typ = buffer_get_data(tmp);
                
                char* key = websocket_generate_sec_websocket_key(&malloc);
                string_safe_assign(&ctx->sec_websocket_key, key);
                free(key);

                buf = websocket_connect_request(domain, domain_port, url_path, ctx->sec_websocket_key, &malloc, &len);
                {
                    char* b64addr = std_base64_encode_alloc(typ, (size_t)typ_len, &malloc);
                    static const char* addr_fmt = "Target-Address" ": %s\r\n";
                    char* addr_field = (char*)calloc(strlen(addr_fmt) + strlen(b64addr) + 1, sizeof(*addr_field));
                    sprintf(addr_field, addr_fmt, b64addr);
                    buf = http_header_append_new_field(buf, &len, &realloc, addr_field);
                    free(addr_field);
                    free(b64addr);
                }
                
                if (ctx->udp_data_ctx) {
                    size_t addr_len = 0;
                    uint8_t* addr_p = socks5_address_binary(&ctx->udp_data_ctx->target_addr, &malloc, &addr_len);
                    char* b64str = url_safe_base64_encode_alloc(addr_p, (size_t)addr_len, &malloc);
                    static const char* udp_fmt = "UDP" ": %s\r\n";
                    char* udp_field = (char*)calloc(strlen(udp_fmt) + strlen(b64str) + 1, sizeof(*udp_field));
                    sprintf(udp_field, udp_fmt, b64str);
                    buf = http_header_append_new_field(buf, &len, &realloc, udp_field);
                    free(udp_field);
                    free(b64str);
                    free(addr_p);
                }
                
                tls_client_send_data(ctx->tls_ctx, buf, len);
                ctx->stage = tunnel_stage_tls_websocket_upgrade;
                free(buf);
            }
            buffer_release(tmp);
//            --------------------------ss-tls-end
    }
    
}

/*
  ssl/tls 发送完毕回调
 */
static void tls_cli_on_write_done(struct tls_cli_ctx* tls_cli, int status, void* p) {
    struct client_ctx* ctx = (struct client_ctx*)p;
    struct tunnel_ctx* tunnel = ctx->tunnel;
    assert(ctx->tls_ctx == tls_cli);
    if (status < 0) {
        char* tmp = socks5_address_to_string(tunnel->desired_addr, &malloc, true);
        char buff[256] = { 0 };
        pr_err("[TLS] write \"%s\" failed: %d: %s", tmp, status, uv_strerror_r(status, buff, sizeof(buff)));
        free(tmp);

        tunnel->tunnel_shutdown(tunnel);
    }
    (void)tls_cli;
    
}

/*
  ssl/tls 接收数据完毕回调
 */
static void tls_cli_on_data_received(struct tls_cli_ctx* tls_cli, int status, const uint8_t* data, size_t size, void* p) {
    struct client_ctx* ctx = (struct client_ctx*)p;
    struct tunnel_ctx* tunnel;

    ASSERT(ctx);
    tunnel = ctx->tunnel;
    ASSERT(tunnel);

    assert(ctx->tls_ctx == tls_cli);

    if (tunnel->tunnel_is_terminated(tunnel)) {
        return;
    }

    if (status < 0) {
        char* tmp = socks5_address_to_string(tunnel->desired_addr, &malloc, true);
        if (status == UV_EOF) {
            (void)tmp; // pr_warn("connection with %s:%d closed abnormally.", tmp, port);
        } else {
//            char buff[256] = { 0 };
//            printf("[TLS] read on %s error %ld: %s", tmp, (long)status, uv_strerror_r((int)status, buff, sizeof(buff)));
        }
        free(tmp);

        tunnel->tunnel_shutdown(tunnel);
        return;
    }

    if (ctx->stage == tunnel_stage_tls_websocket_upgrade) {
        
        struct http_headers* hdrs = http_headers_parse(false, data, size);
        const char* accept_val = http_headers_get_field_val(hdrs, SEC_WEBSOKET_ACCEPT);
        const char* ws_status = http_headers_get_status(hdrs);
        char* calc_val = websocket_generate_sec_websocket_accept(ctx->sec_websocket_key, &malloc);
        size_t pl = http_headers_get_parsed_length(hdrs);
        if (NULL == ws_status ||
            0 != strcmp(WEBSOCKET_STATUS, ws_status) ||
            NULL == accept_val ||
            NULL == calc_val ||
            pl != size ||
            0 != strcmp(accept_val, calc_val))
        {
            char* tmp = socks5_address_to_string(tunnel->desired_addr, &malloc, true);
            printf("[TLS] websocket error at \"%s\" with status: %s\n", tmp, http_headers_get_status(hdrs));
            free(tmp);
            tunnel->tunnel_shutdown(tunnel);
        } else {
            if (ctx->udp_data_ctx) {
                // At this moment, the UDP over TLS connection have established.
                // We needn't send the client incoming data, because we have sent
                // it as payload of WebSocket authenticate package in function
                // `tls_cli_on_connection_established`.
                ctx->stage = tunnel_stage_tls_streaming;
                do {
                    struct buffer_t* tmp; const uint8_t* p; size_t size = 0;
                    const void* udp_pkg = cstl_deque_front(ctx->udp_data_ctx->send_deque);
                    if (udp_pkg == NULL) {
                        break;
                    }
                    tmp = *((struct buffer_t**)udp_pkg);

                    tunnel_cipher_client_encrypt(ctx->cipher, tmp);
                    p = buffer_get_data(tmp);
                    size = buffer_get_length(tmp);
                    tls_cli_send_websocket_data(ctx, p, size);

                    cstl_deque_pop_front(ctx->udp_data_ctx->send_deque);
                } while (true);

            } else {
                do_action_after_auth_server_success(tunnel);
            }
        }
        http_headers_destroy(hdrs);
        free(calc_val);
        return;
    }
    
    else if (ctx->stage == tunnel_stage_tls_streaming) {
        buffer_concatenate_raw(ctx->server_delivery_cache, data, size);
        do {
            ws_frame_info info = { WS_OPCODE_BINARY, 0, 0, 0, 0, 0 };
            struct buffer_t* tmp;
            enum ssr_error e;
            struct buffer_t* feedback = NULL;
            size_t buf_len = buffer_get_length(ctx->server_delivery_cache);
            const uint8_t* buf_data = buffer_get_data(ctx->server_delivery_cache);
            uint8_t* payload = websocket_retrieve_payload(buf_data, buf_len, &malloc, &info);
            (void)e;
            if (payload == NULL) {
                break;
            }
            buffer_shortened_to(ctx->server_delivery_cache, info.frame_size, buf_len - info.frame_size, true);

            if (info.fin && info.masking == false && info.opcode == WS_OPCODE_CLOSE) {
                ws_close_reason reason = WS_CLOSE_REASON_UNKNOWN;
                if (info.payload_size >= sizeof(uint16_t)) {
                    reason = (ws_close_reason)ws_ntoh16(*((uint16_t*)payload));
                }
                if (reason != WS_CLOSE_REASON_NORMAL) {
                    char* target = socks5_address_to_string(tunnel->desired_addr, &malloc, true);
                    const char* fmt = "[TLS] websocket warning at \"%s\" with close reason %s and info \"%s\"";
                    pr_warn(fmt, target, ws_close_reason_string(reason), ((char*)payload)+sizeof(uint16_t));
                    free(target);
                }
                free(payload);
                ctx->tls_is_eof = true;
                break;
            }

            tmp = buffer_create_from(payload, info.payload_size);
            e = tunnel_cipher_client_decrypt(ctx->cipher, tmp, &feedback);
            assert(!feedback);

            if (ctx->udp_data_ctx) {
                struct buffer_t* t2 = buffer_clone(tmp);
                cstl_deque_push_back(ctx->udp_data_ctx->recv_deque, &t2, sizeof(struct buffer_t*));
            }

            buffer_concatenate(ctx->local_write_cache, tmp);

            buffer_release(tmp);
            free(payload);
        } while (true);

#if ANDROID
        if (log_tx_rx) {
            rx += buffer_get_length(ctx->local_write_cache);
        }
#endif

        if ((buffer_get_length(ctx->local_write_cache) == 0) && ctx->tls_is_eof) {
            tunnel->tunnel_shutdown(tunnel);
            return;
        }

        if (ctx->udp_data_ctx) {
            // Write the received remote data back to the connected UDP client.
            do {
                const struct buffer_t* tmp; size_t s = 0; const uint8_t* p;
                const void* udp_pkg = cstl_deque_front(ctx->udp_data_ctx->recv_deque);
                if (udp_pkg == NULL) {
                    break;
                }
                tmp = *((struct buffer_t**)udp_pkg);

                p = buffer_get_data(tmp);
                s = buffer_get_length(tmp);
                udp_relay_send_data(ctx->udp_data_ctx->udp_ctx, &ctx->udp_data_ctx->src_addr, p, s);

                cstl_deque_pop_front(ctx->udp_data_ctx->recv_deque);
            } while (true);

            buffer_reset(ctx->local_write_cache, true);
            return;
        }

        {
            size_t s = buffer_get_length(ctx->local_write_cache);
            const uint8_t* p = buffer_get_data(ctx->local_write_cache);
            if (p && s) {
                tunnel_socket_ctx_write(tunnel, tunnel->incoming, p, s);
                buffer_reset(ctx->local_write_cache, true);
            }
        }
    }
    else {
        ASSERT(false);
    }
    (void)tls_cli;
}

static bool can_auth_none(const struct tunnel_ctx* cx) {
    (void)cx;
    return true;
}

static bool can_auth_passwd(const struct tunnel_ctx* cx) {
    (void)cx;
    return false;
}

static bool can_access(const struct tunnel_ctx* cx, const struct sockaddr* addr) {
    const struct sockaddr_in6* addr6;
    const struct sockaddr_in* addr4;
    const uint32_t* p;
    uint32_t a, b, c, d;

    (void)cx; (void)addr;
#if !defined(NDEBUG)
    return true;
#endif

    /* TODO Implement proper access checks.  For now, just reject
    * traffic to localhost.
    */
    if (addr->sa_family == AF_INET) {
        addr4 = (const struct sockaddr_in*)addr;
        d = ntohl(addr4->sin_addr.s_addr);
        return (d >> 24) != 0x7F; //127
    }

    if (addr->sa_family == AF_INET6) {
        addr6 = (const struct sockaddr_in6*)addr;
        p = (const uint32_t*)&addr6->sin6_addr.s6_addr;
        a = ntohl(p[0]);
        b = ntohl(p[1]);
        c = ntohl(p[2]);
        d = ntohl(p[3]);
        if (a == 0 && b == 0 && c == 0 && d == 1) {
            return false; /* "::1" style address. */
        }
        if (a == 0 && b == 0 && c == 0xFFFF && (d >> 24) == 0x7F) {
            return false; /* "::ffff:127.x.x.x" style address. */
        }
        return true;
    }

    return false;
}

static int deque_compare_e_ptr(const void* left, const void* right) {
    struct buffer_t* l = *((struct buffer_t**)left);
    struct buffer_t* r = *((struct buffer_t**)right);
    return (int)((ssize_t)l - (ssize_t)r);
}

static void deque_free_e(void* ptr) {
    if (ptr) {
        struct buffer_t* p = *((struct buffer_t**)ptr);
        buffer_release(p);
    }
}

struct udp_data_context* udp_data_context_create(void) {
    struct udp_data_context* ptr;
    ptr = (struct udp_data_context*)calloc(1, sizeof(*ptr));
    ptr->send_deque = cstl_deque_new(10, deque_compare_e_ptr, deque_free_e);
    ptr->recv_deque = cstl_deque_new(10, deque_compare_e_ptr, deque_free_e);
    return ptr;
}

void udp_data_context_destroy(struct udp_data_context* ptr) {
    if (ptr) {
        cstl_deque_delete(ptr->send_deque);
        cstl_deque_delete(ptr->recv_deque);
        free(ptr);
    }
}

static void _do_find_upd_tunnel(struct cstl_set* set, const void* obj, cstl_bool* stop, void* p) {
    struct tunnel_ctx* tunnel = (struct tunnel_ctx*)obj;
    struct client_ctx* ctx = (struct client_ctx*)tunnel->data;
    struct udp_data_context* query_data = (struct udp_data_context*)p;
    struct udp_data_context* iter = ctx->udp_data_ctx;
    if (iter) {
        if ((memcmp(&iter->src_addr, &query_data->src_addr, sizeof(union sockaddr_universal)) == 0) &&
            (memcmp(&iter->target_addr, &query_data->target_addr, sizeof(struct socks5_address)) == 0))
        {
            query_data->owner = ctx;
            if (stop) { *stop = cstl_true; }
        }
    }
    (void)set;
}

void udp_on_recv_data(struct client_ssrot_udp_listener_ctx* udp_ctx, const union sockaddr_universal* src_addr, const struct buffer_t* data, void* p) {
    uv_loop_t* loop = udp_relay_context_get_loop(udp_ctx);
    struct server_env_t* env = (struct server_env_t*)loop->data;
    struct server_config* config = env->config;
    struct tunnel_ctx* tunnel = NULL;
    struct client_ctx* ctx = NULL;
    size_t data_len = buffer_get_length(data), frag_number = 0;
    const uint8_t* data_p = buffer_get_data(data);
    struct udp_data_context* query_data;
    const uint8_t* raw_p = NULL; size_t raw_len = 0;
    struct buffer_t* out_ref;

    query_data = udp_data_context_create();
    if (src_addr) {
        query_data->src_addr = *src_addr;
    }

    raw_p = s5_parse_upd_package(data_p, data_len, &query_data->target_addr, &frag_number, &raw_len);
    if (frag_number != 0) {
        pr_err("%s", "[UDP] We don't process fragmented UDP packages and just drop them.");
        udp_data_context_destroy(query_data);
        return;
    }
    if (query_data->target_addr.addr_type == SOCKS5_ADDRTYPE_INVALID) {
        pr_err("%s", "[UDP] target address invalid");
        udp_data_context_destroy(query_data);
        return;
    }

    out_ref = buffer_create_from(raw_p, raw_len);

    cstl_set_container_traverse(env->tunnel_set, &_do_find_upd_tunnel, query_data);
    if (query_data->owner) {
        ctx = query_data->owner;
        ASSERT(ctx->udp_data_ctx);
        udp_data_context_destroy(query_data);
        tunnel = ctx->tunnel;
        if (tunnel && tunnel->tunnel_is_in_streaming && tunnel->tunnel_is_in_streaming(tunnel)) {
            if (ssr_ok != tunnel_cipher_client_encrypt(ctx->cipher, out_ref)) {
                tunnel->tunnel_shutdown(tunnel);
            } else {
                size_t len = buffer_get_length(out_ref); const uint8_t* p = buffer_get_data(out_ref);
                tls_cli_send_websocket_data(ctx, p, len);
            }
            buffer_release(out_ref);
        } else if (ctx->udp_data_ctx) {
            cstl_deque_push_back(ctx->udp_data_ctx->send_deque, &out_ref, sizeof(struct buffer_t*));
        } else {
            UNREACHABLE();
        }
    } else {
        tunnel = tunnel_initialize(loop, NULL, config->idle_timeout, &init_done_cb, env);
        ctx = (struct client_ctx*)tunnel->data;
        ctx->cipher = tunnel_cipher_create(ctx->env, 1452);
        ctx->udp_data_ctx = query_data;
        ctx->udp_data_ctx->udp_ctx = udp_ctx;

        *tunnel->desired_addr = query_data->target_addr;

        ctx->stage = tunnel_stage_tls_connecting;
        ctx->tls_ctx = tls_client_creator(ctx, config);

        client_tunnel_connecting_print_info(tunnel);

        cstl_deque_push_back(ctx->udp_data_ctx->send_deque, &out_ref, sizeof(struct buffer_t*));
    }
    (void)p;
}


//----------------vmess
static bool isVMessConfig(struct server_config* config){
    return (strcasecmp(config->proxytype, "VMESS")==0);
}

/*
  先响应客户端握手>认证(初始化vmess相关参数)
  开始连接服务节点[绑定ssl][建立ws通道]
  读取首包>发送vmess头+首包>进入自动转发流程
 */
static void tunnel_vmess_dispatcher(struct tunnel_ctx* tunnel, struct socket_ctx* socket) {
    struct client_ctx* ctx = (struct client_ctx*)tunnel->data;
//    struct server_env_t* env = ctx->env;
//    struct server_config* config = env->config;
    struct socket_ctx* incoming = tunnel->incoming;
    struct socket_ctx* outgoing = tunnel->outgoing;
    
    const char* info = tunnel_stage_string(ctx->stage);
    strncpy(tunnel->extra_info, info, 0x100 - 1);
    
//    ASSERT(config->over_tls_enable == false);
    switch (ctx->stage) {
    case tunnel_stage_handshake://收到客户端握手请求
        ASSERT(incoming->rdstate == socket_state_done);
        incoming->rdstate = socket_state_stop;
        do_handshake(tunnel);//响应客户端的握手信号
        break;
    case tunnel_stage_handshake_replied:
        ASSERT(incoming->wrstate == socket_state_done);
        incoming->wrstate = socket_state_stop;
        do_wait_client_app_s5_request(tunnel);
        break;
    case tunnel_stage_s5_request_from_client_app:
        ASSERT(incoming->rdstate == socket_state_done);
        incoming->rdstate = socket_state_stop;
        do_parse_s5_request_from_client_app(tunnel,2);
        break;
    case tunnel_stage_s5_udp_accoc:
        ASSERT(incoming->wrstate == socket_state_done);
        incoming->wrstate = socket_state_stop;
        tunnel->tunnel_shutdown(tunnel);
        break;
    case tunnel_stage_s5_response_done:
        ASSERT(incoming->wrstate == socket_state_done);
        incoming->wrstate = socket_state_stop;
        socket_ctx_read(incoming, true);
        ctx->stage = tunnel_stage_client_first_pkg; //连接成功后，读取请求数据,即为首个数据包
        break;
    case tunnel_stage_client_first_pkg:
        ASSERT(incoming->rdstate == socket_state_done);
        incoming->rdstate = socket_state_stop;
        do_common_connet_remote_server(tunnel);  //取得client发来的首个数据包，则开始向ssr节点请求建立连接
        break;
    case tunnel_stage_resolve_ssr_server_host_done: //DNS解析完成
        do_resolve_ssr_server_host_aftercare(tunnel);
        break;
    case tunnel_stage_connect_ssr_server_done:
        vmess_myabe_ws_ssl_handshake(tunnel);//与服务连接成功后，进行ws握手，或ssl绑定
        break;
    case tunnel_stage_ssr_auth_sent: //已发ws认证请求
        ASSERT(outgoing->wrstate == socket_state_done);
        outgoing->wrstate = socket_state_stop;
        vmess_waiting_ws_server_feedback(tunnel);
        break;
    case tunnel_stage_tls_websocket_upgrade:
        ASSERT(outgoing->rdstate == socket_state_done);
        outgoing->rdstate=socket_state_stop;
        vmess_prase_websocket_feedback(tunnel); //解析ws是否建立成功
        break;
    case tunnel_stage_auth_completion_done: //认证成功，开始发送首包
        vmess_send_first_package(tunnel);
        break;
    case tunnel_stage_streaming:
        tunnel_vmess_client_streaming(tunnel, socket);
        break;
    case tunnel_stage_kill:
        tunnel->tunnel_shutdown(tunnel);
        break;
    default:
        UNREACHABLE();
    }
}

static bool tunnel_vmess_is_in_streaming(struct tunnel_ctx* tunnel) {
    struct client_ctx* ctx = (struct client_ctx*)tunnel->data;
    return (ctx && ctx->stage == tunnel_stage_streaming);
}

static void vmess_init_outbound(struct tunnel_ctx* tunnel,const uint8_t* data,size_t size){
    struct client_ctx* ctx = (struct client_ctx*)tunnel->data;
    struct server_env_t* env = ctx->env;
    struct server_config* config = env->config;
    
    tunnel->outbound = hl_session_outbound_new();
    toto_session_outbound_t *ptr=tunnel->outbound;
    
    ptr->tunnel=tunnel;
    ptr->outbound_socket_ctx_write_fn = &vmess_socket_write_data; //反向指回来，后面发送数据时，需用到tunnel->outbound_socket_ctx_write_fn即可
    ptr->server_config=hl_config_parse_servers(config); //初始化vmess配置，特殊处理password等

//    uint8_t atype = 0;
//    socks5_dest_addr_parse(data, size, &atype, &ptr->dest, &ptr->port); //得到dest和port
    
    toto_cryptor_type_t cipherType=AES_128_CFB;
    if (strcmp(config->method, "chacha20-ietf-poly1305")==0) { 
        cipherType=AEAD_CHACHA20_POLY1305;
    }else if (strcmp(config->method, "aes-128-gcm")==0) {
        cipherType=AEAD_AES_128_GCM;
    }else if (strcmp(config->method, "aes-128-cfb")==0) {
        cipherType=AES_128_CFB;
    }else{
        cipherType=AEAD_CHACHA20_POLY1305; //auto，或不支持的，默认为AEAD_CHACHA20_POLY1305
    }
    ptr->ctx = hl_outbound_ctx_v2ray_new(data, size, cipherType); //创建VMess上下文,data为socks5认证请求数据(内有destAddr+destPort)
    
}

/*
 服务节点连接成功，则进行ssl、ws认证
 */
static void vmess_myabe_ws_ssl_handshake(struct tunnel_ctx* tunnel){
    if (tunnel->is_ws_protocol){ //hl_vmess_WS_Enable(tunnel->outbound->server_config)
        struct client_ctx* ctx = (struct client_ctx*)tunnel->data;
        struct server_env_t* env = ctx->env;
        struct server_config* config = env->config;
        struct socket_ctx* outgoing = tunnel->outgoing;
        
        const char* ws_path = config->over_tls_path;
        const char* ws_host = (strlen(config->over_tls_server_domain)>0)?config->over_tls_server_domain:config->remote_host;
        const char* server_host = config->remote_host;
        unsigned short server_port = config->remote_port;
        uint8_t* ws_buf = NULL;
        size_t ws_len = 0;
/*
测试发现用websocket_generate_sec_websocket_key生成的key，服务返回（400:bad Sec-WebSocket-Key）：
"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 47\r\n\r\nhandshake error: bad \"Sec-WebSocket-Key\" header"
改用常量key["dGhlIHNhbXBsZSBub25jZQ=="]，返回：
"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"
*/
        ws_buf = websocket_connect_request_Ex(ws_host, ws_path, server_host,server_port, ws_key, &malloc, &ws_len);
        tunnel_socket_ctx_write(tunnel, outgoing, ws_buf, ws_len);
        ctx->stage = tunnel_stage_ssr_auth_sent;
        free(ws_buf);
    }
    else{
//如果不是ws协议，则直接tunnel_stage_auth_completion_done>do_launch_streaming>开始发送vmess协议头及首个数据包
        do_action_after_auth_server_success(tunnel);
    }
    return;
 
}

static void vmess_waiting_ws_server_feedback(struct tunnel_ctx* tunnel) {
    struct socket_ctx* incoming = tunnel->incoming;
    struct socket_ctx* outgoing = tunnel->outgoing;
    struct client_ctx* ctx = (struct client_ctx*)tunnel->data;

    ASSERT(incoming->rdstate == socket_state_stop);
    ASSERT(incoming->wrstate == socket_state_stop);
    ASSERT(outgoing->rdstate == socket_state_stop);
    ASSERT(outgoing->wrstate == socket_state_stop);

    if (outgoing->result < 0) { //说明发送ws认证失败,应该为=0，表示发送成功
        char buff[256] = { 0 };
        pr_err("write error: %s", uv_strerror_r((int)outgoing->result, buff, sizeof(buff)));
        tunnel->tunnel_shutdown(tunnel);
        return;
    }
  
    if (tunnel->is_ws_protocol) {//hl_vmess_WS_Enable(tunnel->outbound->server_config)
        socket_ctx_read(outgoing, true);
        ctx->stage = tunnel_stage_tls_websocket_upgrade;
    }
    else{
        do_action_after_auth_server_success(tunnel); //非ws协议，则接下来>直接发送vmess协议头及首个数据包
    }
    
}

/*
  vmess-ws协议握手是否成功
 */
static void vmess_prase_websocket_feedback(struct tunnel_ctx* tunnel) {
    struct socket_ctx* incoming = tunnel->incoming;
    struct socket_ctx* outgoing = tunnel->outgoing;
    struct client_ctx* ctx = (struct client_ctx*)tunnel->data;

    ASSERT(incoming->rdstate == socket_state_stop);
    ASSERT(incoming->wrstate == socket_state_stop);
    ASSERT(outgoing->rdstate == socket_state_stop);
    ASSERT(outgoing->wrstate == socket_state_stop);

    if (outgoing->result <= 0) {
        char buff[256] = { 0 };
        pr_err("write error: %s", uv_strerror_r((int)outgoing->result, buff, sizeof(buff)));
        tunnel->tunnel_shutdown(tunnel);
        return;
    }
    
    if (outgoing->buf==NULL) {
        printf("ws-connect-fail: null\n");
        tunnel->tunnel_shutdown(tunnel);
        return;
    }
    
    uint8_t* data = (uint8_t*)outgoing->buf->base;
/*
 成功时，服务返回数据如下：
     "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"
 */
    
    if (vmess_ws_upgrade_check((char *)data)) {
        printf("ws-connect-fail:%s\n",data);
        tunnel->tunnel_shutdown(tunnel);
        return;
    }
    tunnel->outbound->ready=true; //表示可以发送vmess协议数据了
    
    ctx->stage = tunnel_stage_auth_completion_done;
    tunnel->tunnel_dispatcher(tunnel, outgoing);
}

static void vmess_send_first_package(struct tunnel_ctx* tunnel) {
    struct client_ctx* ctx = (struct client_ctx*)tunnel->data;
    struct socket_ctx* incoming = tunnel->incoming;
    struct socket_ctx* outgoing = tunnel->outgoing;

    ASSERT(incoming->rdstate == socket_state_stop);
    ASSERT(incoming->wrstate == socket_state_stop);
    ASSERT(outgoing->rdstate == socket_state_stop);
    ASSERT(outgoing->wrstate == socket_state_stop);

    if (incoming->result < 0) { //>0，收到的首包数据长度
        char buff[256] = { 0 };
        pr_err("write error: %s", uv_strerror_r((int)incoming->result, buff, sizeof(buff)));
        tunnel->tunnel_shutdown(tunnel);
        return;
    }

    //ws发送vmess协议头+首个数据包
    const uint8_t* out_data = NULL;
    size_t out_data_len = buffer_get_length(ctx->first_client_pkg);
    if (!out_data_len) {
        buffer_reset(ctx->first_client_pkg, true);
        tunnel->tunnel_shutdown(tunnel);
        return;
    }
    
    struct buffer_t* tmp = buffer_create(out_data_len);
    buffer_replace(tmp, ctx->first_client_pkg);
    out_data=buffer_get_data(tmp);
    out_data_len=buffer_get_length(tmp);//发现数据长度为517，但out_data的内存数据后面都是0x00
//    size_t s_len=strlen(out_data); //=4，因为第5个是0x00
    buffer_reset(ctx->first_client_pkg, true);
    

    hl_vmess_write_data_2_remote(tunnel->outbound,out_data,out_data_len);
    buffer_release(tmp);
    
    socket_ctx_read(incoming, false);
    socket_ctx_read(outgoing, true);
    ctx->stage = tunnel_stage_streaming;
    
}

static void tunnel_vmess_client_streaming(struct tunnel_ctx* tunnel, struct socket_ctx* socket) {
    struct socket_ctx* current_socket = socket;
//    struct socket_ctx* target_socket = NULL;
   
//    struct client_ctx* ctx = (struct client_ctx*)tunnel->data;
 
    ASSERT(socket->rdstate == socket_state_done || socket->wrstate == socket_state_done);
    
    if (socket->wrstate == socket_state_done) {
            socket->wrstate = socket_state_stop;
            return;
    } else if (socket->rdstate == socket_state_done) {
        socket->rdstate = socket_state_stop;
    } else {
        UNREACHABLE();
    }
    
    ASSERT(current_socket == tunnel->incoming || current_socket == tunnel->outgoing);
    
    size_t len = 0;
    len=(size_t)current_socket->result;
    if (!len) {
        return;
    }

    struct buffer_t *tmp=buffer_create_from((uint8_t*)current_socket->buf->base, current_socket->buf->len);
    if (tmp /* && len > 0 */) {
        uint8_t* buf =  (uint8_t*)malloc(len + 1);
        memcpy(buf, buffer_get_data(tmp), len);
        buf[len] = 0;
        
        if (current_socket == tunnel->incoming) {
            hl_vmess_write_data_2_remote(tunnel->outbound,buf,len);
        }else if(current_socket==tunnel->outgoing){
            if (tunnel->is_ws_protocol) { //hl_vmess_WS_Enable(tunnel->outbound->server_config)
                vmess_ws_decode_recv_data(tunnel,buf,len); //ws解析>vmess解密>incoming转发给client
            }else{
                size_t olen=0;
                hl_vmess_write_data_2_local(tunnel->outbound, buf, len, &olen);//vmess解密>incoming转发给client
            }
        }else{
            tunnel->tunnel_shutdown(tunnel);
        }
        
        free(buf);
    } else {
        tunnel->tunnel_shutdown(tunnel);
    }
    buffer_release(tmp);
}


static void vmess_socket_write_data(toto_session_outbound_t* outbound, const void* data, size_t len,bool is2Local){
    struct tunnel_ctx* tunnel=(struct tunnel_ctx*)outbound->tunnel;
    if (!tunnel) {
        tunnel->tunnel_shutdown(tunnel);
        return;
    }
    
    if (is2Local) {
        struct socket_ctx* incoming = tunnel->incoming;
        tunnel_socket_ctx_write(tunnel, incoming, data, len);
//        printf("vmess_socket_write_data>to-Local>%zu\n",len);
    }else{
        struct socket_ctx* outgoing = tunnel->outgoing;
        //此时data为vmess加密后的data，进一步判断是否需要ws协议封装
        if (tunnel->is_ws_protocol) {//hl_vmess_WS_Enable(outbound->server_config)
            vmess_ws_write_frame_2_remtoe(tunnel,data,len);
        }
        else{
            tunnel_socket_ctx_write(tunnel, outgoing, data, len);
//            printf("vmess_socket_write_data>to-Server>%zu\n",len);
        }
    }
}

static void vmess_ws_write_frame_2_remtoe(struct tunnel_ctx* tunnel, const uint8_t* vmess_buf, size_t vmess_len) {
    ws_frame_info info = { WS_OPCODE_BINARY, true, true, 0, 0, 0 };
    uint8_t* frame;
    ws_frame_binary_alone(true, &info);
    frame = websocket_build_frame_with_mask0(&info, vmess_buf, vmess_len, &malloc);
    struct socket_ctx* outgoing = tunnel->outgoing;
    tunnel_socket_ctx_write(tunnel, outgoing, frame, info.frame_size);
//    printf("vmess_ws_write_frame_2_remtoe>to-Server>%zu\n",info.frame_size);
    free(frame);
}

static void vmess_ws_decode_recv_data(struct tunnel_ctx* tunnel,uint8_t* data, size_t size){
    struct client_ctx* ctx = (struct client_ctx*)tunnel->data;
    buffer_concatenate_raw(ctx->server_delivery_cache, data, size);
    do {
        ws_frame_info info = { WS_OPCODE_BINARY, 0, 0, 0, 0, 0 }; //服务端发来的数据，一般不会使用mask
//        struct buffer_t* tmp;
        size_t buf_len = buffer_get_length(ctx->server_delivery_cache);
        const uint8_t* buf_data = buffer_get_data(ctx->server_delivery_cache);
        uint8_t* payload = websocket_retrieve_payload(buf_data, buf_len, &malloc, &info);

        if (payload == NULL) {//一般都是当长度不够时，此时会返回null，等待下一个包续接数据
            break;
        }
        buffer_shortened_to(ctx->server_delivery_cache, info.frame_size, buf_len - info.frame_size, true);  //解析出一段，就清掉一段

        if (info.fin && info.masking == false && info.opcode == WS_OPCODE_CLOSE) {
            ws_close_reason reason = WS_CLOSE_REASON_UNKNOWN;
            if (info.payload_size >= sizeof(uint16_t)) {
                reason = (ws_close_reason)ws_ntoh16(*((uint16_t*)payload));
            }
            if (reason != WS_CLOSE_REASON_NORMAL) {
                char* target = socks5_address_to_string(tunnel->desired_addr, &malloc, true);
                const char* fmt = "[vmess] websocket warning at \"%s\" with close reason %s and info \"%s\"";
                pr_warn(fmt, target, ws_close_reason_string(reason), ((char*)payload)+sizeof(uint16_t));
                free(target);
            }
            free(payload);
            ctx->tls_is_eof = true;
            break;
        }
        
        size_t decode_len=0;
        hl_vmess_write_data_2_local(tunnel->outbound, payload, info.payload_size, &decode_len);//vmess解密>incoming转发给client
//        printf("hl_vmess_write_data_2_local>payload[%zu]\n",info.payload_size); //info.payload_size<=2048
//        hl_decode_vemss_data(tunnel->outbound,payload,info.payload_size,&decode_len); //ws解析出来的数据，还需经过vmess解析+解密,然后直接发送给local
        free(payload);
    } while (true);
}


//-----------ss
static bool isSSConfig(struct server_config* config){
    return (strcasecmp(config->proxytype, "SS")==0);
}

static void tunnel_SS_dispatcher(struct tunnel_ctx* tunnel, struct socket_ctx* socket){
    struct client_ctx* ctx = (struct client_ctx*)tunnel->data;
//    struct server_env_t* env = ctx->env;
//    struct server_config* config = env->config;
    struct socket_ctx* incoming = tunnel->incoming;
    struct socket_ctx* outgoing = tunnel->outgoing;
    
    const char* info = tunnel_stage_string(ctx->stage);
    strncpy(tunnel->extra_info, info, 0x100 - 1);

    switch (ctx->stage) {
    case tunnel_stage_handshake://收到客户端握手请求
        ASSERT(incoming->rdstate == socket_state_done);
        incoming->rdstate = socket_state_stop;
        do_handshake(tunnel);//响应客户端的握手信号
        break;
    case tunnel_stage_handshake_replied:
        ASSERT(incoming->wrstate == socket_state_done);
        incoming->wrstate = socket_state_stop;
        do_wait_client_app_s5_request(tunnel);
        break;
    case tunnel_stage_s5_request_from_client_app:
        ASSERT(incoming->rdstate == socket_state_done);
        incoming->rdstate = socket_state_stop;
        do_parse_s5_request_from_client_app(tunnel,1);
        break;
    case tunnel_stage_s5_udp_accoc:
        ASSERT(incoming->wrstate == socket_state_done);
        incoming->wrstate = socket_state_stop;
        tunnel->tunnel_shutdown(tunnel);
        break;
    case tunnel_stage_s5_response_done:
        ASSERT(incoming->wrstate == socket_state_done);
        incoming->wrstate = socket_state_stop;
        socket_ctx_read(incoming, true);
        ctx->stage = tunnel_stage_client_first_pkg; //连接成功后，读取请求数据,即为首个数据包
        break;
    case tunnel_stage_client_first_pkg:
        ASSERT(incoming->rdstate == socket_state_done);
        incoming->rdstate = socket_state_stop;
        do_common_connet_remote_server(tunnel);  //取得client发来的首个数据包，则开始向ssr节点请求建立连接
        break;
    case tunnel_stage_resolve_ssr_server_host_done: //DNS解析完成
        do_resolve_ssr_server_host_aftercare(tunnel);
        break;
    case tunnel_stage_connect_ssr_server_done:
            totovpn_do_ss_handshake(tunnel);//与服务连接成功后，进行http(ws)握手，或tls/ssl绑定
        break;
    case tunnel_stage_ssr_auth_sent:
        ASSERT(outgoing->wrstate == socket_state_done);
        outgoing->wrstate = socket_state_stop;
            
        totovpn_waiting_ss_handshake_feedback(tunnel);
        break;
    case tunnel_stage_tls_websocket_upgrade: //ws/tls-ss
        if(outgoing->rdstate == socket_state_done)
            outgoing->rdstate=socket_state_stop;
        
        if(outgoing->wrstate == socket_state_done)
            outgoing->wrstate = socket_state_stop;
            
        totovpn_prase_ss_handshake_feedback(tunnel);
        break;
    case tunnel_stage_ssr_server_feedback_arrived: //普通tcp-ss
        ASSERT(outgoing->rdstate == socket_state_done);
        outgoing->rdstate = socket_state_stop;
        if (do_ssr_receipt_for_feedback(tunnel) == false) {
//ssr回应认证成功，并且不需回复确认收到认证成功，则下一步表明认证完成>tunnel_stage_auth_completion_done
            do_action_after_auth_server_success(tunnel);
        }else{
//   否则会在do_ssr_receipt_for_feedback里回复ssr我们到到了认证成功的回应，接着下一步>tunnel_stage_ssr_receipt_to_server_sent
       }
        break;
    case tunnel_stage_ssr_receipt_to_server_sent:
        ASSERT(outgoing->wrstate == socket_state_done);
        outgoing->wrstate = socket_state_stop;
        do_action_after_auth_server_success(tunnel);//已回复ssr我们收到认证成功的消息，则表明认证完成
        break;
    case tunnel_stage_auth_completion_done: //认证成功，开始发送首包
        ASSERT(incoming->rdstate == socket_state_stop);
        ASSERT(incoming->wrstate == socket_state_stop);
        ASSERT(outgoing->rdstate == socket_state_stop);
        ASSERT(outgoing->wrstate == socket_state_stop);
        do_totovpn_launch_streaming(tunnel); //握手成功后开始发送首包
        break;
    case tunnel_stage_streaming:
        tunnel_totovpn_client_streaming(tunnel, socket);
        break;
    case tunnel_stage_kill:
        tunnel->tunnel_shutdown(tunnel);
        break;
    default:
        UNREACHABLE();
    }
}


/*
 服务节点连接成功，则进行tcp/tls/ws认证
 普通tcp传输(即obfs为空)时，只需发送type+host+port进行通知服务节点
 obfs=tls时，需要进行tls协议握手
 obfs=http时，需要进行websocket握手
 */
static void totovpn_do_ss_handshake(struct tunnel_ctx* tunnel){
// ss obfs参数只有2种方式，要么是obfs=tls走tls/ssl-tls1.2_ticket_auth，要么是obfs=http走ws--http_simple
    struct client_ctx* ctx = (struct client_ctx*)tunnel->data;
//    struct server_env_t* env = ctx->env;
//    struct server_config* config = env->config;
    
    struct socket_ctx* incoming = tunnel->incoming;
    struct socket_ctx* outgoing = tunnel->outgoing;
    
    ASSERT(incoming->rdstate == socket_state_stop);
    ASSERT(incoming->wrstate == socket_state_stop);
    ASSERT(outgoing->rdstate == socket_state_stop);
    ASSERT(outgoing->wrstate == socket_state_stop);
    
    if (outgoing->result != 0) {
        /* Send a 'Connection refused' reply. */
        tunnel_socket_ctx_write(tunnel, incoming, "\5\5\0\1\0\0\0\0\0\0", 10);
        ctx->stage = tunnel_stage_kill;
//        UNREACHABLE();
        tunnel->tunnel_shutdown(tunnel);
        return;
    }
    
    if (tunnel->is_ws_protocol) {//--------ws
        printf("is_ws_protocol\n"); //还没调通,need.update
    }
    else if (tunnel->is_tls_protocol) {//--------tls
//       进行tls协议组装，发送tls握手
        totovpn_init_obfs(tunnel,true);
//第一种方案，先发送握手协议+destAddr信息（速度有点慢）
//         uint8_t* out_data = NULL;
        size_t out_data_len = 0;
        uint8_t *out_data=hl_totovpn_encrypt_remote_data(tunnel->outbound,NULL,0,&out_data_len); //先获得首个加密数据(type+host+port)
        if (out_data==NULL) {
            tunnel->tunnel_shutdown(tunnel);
            return;
        }
// 组装tls握手协议
        struct buffer_t *buf=buffer_create_from(out_data, out_data_len);
        size_t ilen=ss_obfs_tls_req_package(buf,tunnel->ss_obfs);
// 发送握手
        const uint8_t *encode_data=buffer_get_data(buf);
        tunnel_socket_ctx_write(tunnel, outgoing, encode_data, ilen);
//        printf("ss_write_to_remote>%zu\n",ilen);
        buffer_release(buf);
        ctx->stage = tunnel_stage_ssr_auth_sent; //等待节点响应
        
    }
    else{//----------http
//       此种情况下，即可以直接为没有插件协议、没有混淆协议的ssr类型，直接走ssr类型即可通信
        //普通tcp收发,没有plugin或obfs参数的情况，直接加密方法加密，然后按shadowsocks规则发送
        totovpn_send_ss_header(ctx,false);
    }
 
}


static void totovpn_waiting_ss_handshake_feedback(struct tunnel_ctx* tunnel) {
    struct socket_ctx* incoming = tunnel->incoming;
    struct socket_ctx* outgoing = tunnel->outgoing;
    struct client_ctx* ctx = (struct client_ctx*)tunnel->data;

    ASSERT(incoming->rdstate == socket_state_stop);
    ASSERT(incoming->wrstate == socket_state_stop);
    ASSERT(outgoing->rdstate == socket_state_stop);
    ASSERT(outgoing->wrstate == socket_state_stop);

    if (outgoing->result < 0) { //说明发送ws认证失败,应该为=0，表示发送成功
        char buff[256] = { 0 };
        pr_err("write error: %s", uv_strerror_r((int)outgoing->result, buff, sizeof(buff)));
        tunnel->tunnel_shutdown(tunnel);
        return;
    }

    if (tunnel->is_tls_protocol) {//------tls(obfs=tls)
//ss-tls混淆握手后是没有数据回应的,直接进到首包发送
        ctx->stage = tunnel_stage_auth_completion_done; //不读取首个响应，直接发送首包，那随后的响应必有iv+响应数据才对
        tunnel->tunnel_dispatcher(tunnel, outgoing);
        
//或者也读取握手响应，服务只会返回一个iv头，用于ssClient解密
//        socket_ctx_read(outgoing, true);
//        ctx->stage = tunnel_stage_tls_websocket_upgrade; //发送tls握手后，读取节点响应
    }
    else if (tunnel->is_ws_protocol) {//------ws(obfs=http),尚未调通.need.update
//而ss-http，会有一个空包回应,只需看http头部是否为101握手确认
        socket_ctx_read(outgoing, true);
        ctx->stage = tunnel_stage_tls_websocket_upgrade; //不管是tls或ws都走tunnel_stage_tls_websocket_upgrade
        
//        ss_buffer_t *tmpBuf=(ss_buffer_t *)ss_malloc(sizeof(ss_buffer_t));
//        ss_balloc(tmpBuf, SSR_BUFF_SIZE);
//
//        const uint8_t* out_data = NULL; size_t out_data_len = 0;
//        struct buffer_t* tmp = buffer_create(SSR_BUFF_SIZE);
//        buffer_replace(tmp, ctx->first_client_pkg);
//
//        if (ssr_ok != tunnel_cipher_client_encrypt(ctx->cipher, tmp)) { //加密后，tmp->len=0 ？
//            buffer_release(tmp);
//            tunnel->tunnel_shutdown(tunnel);
//            return;
//        }
//
//        _do_protect_socket(tunnel, uv_stream_fd(&outgoing->handle.tcp)); //android才需要
//
//        out_data = buffer_get_data(tmp);
//        out_data_len = buffer_get_length(tmp);
//        tmpBuf->len=out_data_len;
//        memcpy(tmpBuf->data, out_data, out_data_len);
//        buffer_release(tmp);
//
////#define BUF_SIZE 2048
//        size_t ilen = tunnel->ss_obfs_para->obfs_request(tmpBuf,SSR_BUFF_SIZE,tunnel->ss_obfs);
//        tunnel_socket_ctx_write(tunnel, outgoing, tmpBuf->data, ilen);
//
//        ss_bfree(tmpBuf,true);
//
//        ctx->stage = tunnel_stage_tls_websocket_upgrade;
        
    }else{//普通tcp-ss //------tcp(obfs=tcp)
//ss-tcp模式，没有协议插件或混淆方法，握手时服务不会响应，只会自动根据接收到的destAddr+port进行与服务站点的连接
        if (tunnel_cipher_client_need_feedback(ctx->cipher)) { //是以混淆方法来判断是否需握手确认响应，ss的(tcp\tls是没有的，而http模式则有回应)
            socket_ctx_read(outgoing, true); //如果握手会有响应的，则读取响应
            ctx->stage = tunnel_stage_ssr_server_feedback_arrived; //不会走此处
        } else {
            ctx->stage = tunnel_stage_auth_completion_done;
            tunnel->tunnel_dispatcher(tunnel, outgoing);
        }
    }
    
}

/*
  ss-ws协议或tls协议 握手是否成功
 */
static void totovpn_prase_ss_handshake_feedback(struct tunnel_ctx* tunnel) {
    struct socket_ctx* incoming = tunnel->incoming;
    struct socket_ctx* outgoing = tunnel->outgoing;
    struct client_ctx* ctx = (struct client_ctx*)tunnel->data;

    ASSERT(incoming->rdstate == socket_state_stop);
    ASSERT(incoming->wrstate == socket_state_stop);
    ASSERT(outgoing->rdstate == socket_state_stop);
    ASSERT(outgoing->wrstate == socket_state_stop);

    if (outgoing->result <= 0) {
        char buff[256] = { 0 };
        pr_err("write error: %s", uv_strerror_r((int)outgoing->result, buff, sizeof(buff)));
        tunnel->tunnel_shutdown(tunnel);
        return;
    }

    if (outgoing->buf==NULL) {
        printf("ss-auth-fail: null\n");
        tunnel->tunnel_shutdown(tunnel);
        return;
    }

    uint8_t* data = (uint8_t*)outgoing->buf->base;
    size_t data_len=outgoing->buf->len;

//    struct server_env_t* env = ctx->env;
//    struct server_config* config = env->config;
    if (tunnel->is_ws_protocol) {//------ws(obfs=http)
        /*
         成功时，服务返回数据如下：
             "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"
         */
        
        if (vmess_ws_upgrade_check((char *)data)) {
            printf("ws-connect-fail:%s\n",data);
            tunnel->tunnel_shutdown(tunnel);
            return;
        }
        ctx->stage = tunnel_stage_auth_completion_done;
        tunnel->tunnel_dispatcher(tunnel, outgoing);
    }
    else if (tunnel->is_tls_protocol){//------tls(obfs=tls)
// ss-tls,握手成功后服务不会响应，
//握手成功拿到解密iv,先解析再解密
        buffer_concatenate_raw(ctx->server_delivery_cache, data, data_len);
        size_t decode_len=0;
        int iResult=ss_obfs_tls_rsp_package(ctx->server_delivery_cache,tunnel->ss_obfs,&decode_len);
        if (OBFS_TLS_ERROR==iResult) {
            buffer_shortened_to(ctx->server_delivery_cache, buffer_get_length(ctx->server_delivery_cache), 0, true); //清空数据
            tunnel->tunnel_shutdown(tunnel);
            return;
        }
        else if (decode_len>0) {
            const uint8_t *buf_data=buffer_get_data(ctx->server_delivery_cache);
            size_t buf_len=buffer_get_length(ctx->server_delivery_cache);
            assert(buf_len>=decode_len);
            
            buffer_shortened_to(ctx->server_delivery_cache, decode_len, buf_len-decode_len, true);
            buf_len=buffer_get_length(ctx->server_delivery_cache);
//                只要是解析出的完整数据不管有否解密成功都要清掉，未解密成功的数据(一般是payloadlen偏大的数据)，缓存起来留待更多数据一起解密
            
            buffer_concatenate_raw(ctx->local_write_cache, buf_data, decode_len); //解析成功的数据加到解密缓存
            
            const uint8_t *encrypt_data=buffer_get_data(ctx->local_write_cache);
            size_t encrypt_len=buffer_get_length(ctx->local_write_cache);
            size_t olen=0,decrypt_len=0;
            if (!hl_totovpn_decrypt_local_data(tunnel->outbound,encrypt_data,encrypt_len,&olen,&decrypt_len)){
                buffer_shortened_to(ctx->server_delivery_cache, buf_len, 0, true); //清空数据
                buffer_shortened_to(ctx->local_write_cache, encrypt_len, 0, true); //清空数据
                tunnel->tunnel_shutdown(tunnel);
                return;
            }
            if (decode_len==decrypt_len) {
//解析数据刚好完全解密，则清掉解密缓存
                buffer_shortened_to(ctx->local_write_cache, encrypt_len, 0, true); //清空数据
            }
            else{ //解密成功，但只有部分解密了，则要将已解密的数据从解密缓存中去掉
// 会有decode_len=16384，decrypt_len=18的情况，解密的时候发现剩余len没有plen大，数据长度不够，此时需加回17 03 03以便下一次解密
                if (decrypt_len>0) {
//表示已有发送过完整数据，需将已发送的数据cut掉
                    buffer_shortened_to(ctx->local_write_cache, decrypt_len, encrypt_len-decrypt_len, true);
                }
            }
            
        }
        
        
//将ctx->server_delivery_cache进行解密
        ctx->stage = tunnel_stage_auth_completion_done;
        tunnel->tunnel_dispatcher(tunnel, outgoing);
       
    }
    else{//------tcp(obfs=tcp)
//ss-tcp,握手成功后服务不会响应， --不会走到这里
        
    }

}

static void totovpn_send_ss_header(struct client_ctx* ctx,bool is_tls){
    /*
     shadowsocks数据发送格式
    +-----+-------+-------+------------------+
    | 类型 | 目标  |  端口  |     数据          |
    +-----+-------+-------+------------------+
    | 1   | 变长   |   2   |     变长          |
    +-----+-------+-------+------------------+
     类型 =0x1 目标部分是 IPV4 地址,
         =0x03 目标部分是域名，是变长字符串，第一个字节表示后面数据的长度。
         =0x04 目标部分是一个16字节的 IPV6 地址
     数据部分,就是用户原始的请求（TCP或UDP数据包部分）
     
     而ssServer返回的内容，只是用加密方法加密，不会添加任何额外的头部，直接把原始数据返回。
     */

//ss要么是tls，要么是http(ws),要么是直接tcp；没有wss情况(tls+ws)
    
    struct tunnel_ctx* tunnel = ctx->tunnel;
    struct socket_ctx* outgoing = tunnel->outgoing;
    
    const uint8_t* out_data = NULL; size_t out_data_len = 0;
    struct buffer_t* tmp = buffer_create(SSR_BUFF_SIZE);
    buffer_replace(tmp, ctx->init_pkg);//init_pkg为请求的目标地址及port信息,如 0x03www.youtube.com0x010xbb(cmd[1]+destAdrr[]+destPort[2])
    
    if (ssr_ok != tunnel_cipher_client_encrypt(ctx->cipher, tmp)) { //加密、混淆shadowsocks-header(类型|目标地址|端口)
        buffer_release(tmp);
        tunnel->tunnel_shutdown(tunnel);
        return;
    }

    _do_protect_socket(tunnel, uv_stream_fd(&outgoing->handle.tcp)); //android才需要

    out_data = buffer_get_data(tmp);
    out_data_len = buffer_get_length(tmp);
//    发送shadowsocks-header，进行shadowsocks握手认证,

    if (is_tls) {
        tls_client_send_data(ctx->tls_ctx, out_data, out_data_len);
        ctx->stage = tunnel_stage_tls_websocket_upgrade; //数据回应在tls_cli_on_data_received里
    }else{
        tunnel_socket_ctx_write(tunnel, outgoing, out_data, out_data_len);
        ctx->stage = tunnel_stage_ssr_auth_sent;
    }
    buffer_release(tmp);
}

/*
  ss协议握手成功后，开始进行数据包的发送
 */
static void do_totovpn_launch_streaming(struct tunnel_ctx* tunnel) {
    struct client_ctx* ctx = (struct client_ctx*)tunnel->data;
    struct socket_ctx* incoming = tunnel->incoming;
    struct socket_ctx* outgoing = tunnel->outgoing;

    ASSERT(incoming->rdstate == socket_state_stop);
    ASSERT(incoming->wrstate == socket_state_stop);
    ASSERT(outgoing->rdstate == socket_state_stop);
    ASSERT(outgoing->wrstate == socket_state_stop);

    if (incoming->result < 0) {
        char buff[256] = { 0 };
        pr_err("write error: %s", uv_strerror_r((int)incoming->result, buff, sizeof(buff)));
        tunnel->tunnel_shutdown(tunnel);
        return;
    }
    
//    struct server_env_t* env = ctx->env;
//    struct server_config* config = env->config;
    if (tunnel->is_ws_protocol){
//ss-http
        printf("test.http.first.pack\n");
    }
    else if (tunnel->is_tls_protocol) {
//ss-tls
        const uint8_t* out_data = buffer_get_data(ctx->first_client_pkg);
        size_t out_data_len = buffer_get_length(ctx->first_client_pkg);
//加密、组装首个web请求包
        size_t back_len=0;
        uint8_t *back_data=hl_totovpn_encrypt_remote_data(tunnel->outbound,out_data,out_data_len,&back_len);
        if (back_data==NULL) {
            tunnel->tunnel_shutdown(tunnel);
            return;
        }
        
        struct buffer_t *buf=buffer_create_from(back_data, back_len);
        size_t ilen=ss_obfs_tls_req_package(buf,tunnel->ss_obfs);
// 发送首个web请求数据包
        const uint8_t* encode_data=buffer_get_data(buf);
        tunnel_socket_ctx_write(tunnel, outgoing, encode_data, ilen);
//        printf("ss_write_firstReq_to_remote>%zu\n",ilen);
        buffer_release(buf);
        buffer_reset(ctx->first_client_pkg, true);
    }
    else{
//ss-tcp
        const uint8_t* out_data = NULL;
        size_t out_data_len = 0;
        struct buffer_t* tmp = buffer_create(SSR_BUFF_SIZE);
        buffer_replace(tmp, ctx->first_client_pkg);

        if (ssr_ok != tunnel_cipher_client_encrypt(ctx->cipher, tmp)) {//加密首个web请求数据包
            buffer_release(tmp);
            tunnel->tunnel_shutdown(tunnel);
            return;
        }
        out_data = buffer_get_data(tmp); //out_data为加密后的数据
        out_data_len = buffer_get_length(tmp);
        
        tunnel_socket_ctx_write(tunnel, outgoing, out_data, out_data_len);
        buffer_release(tmp);
        buffer_reset(ctx->first_client_pkg, true);
    }

    socket_ctx_read(incoming, tunnel->is_tls_protocol); //接收httpRroxy转发来的数据
 
    socket_ctx_read(outgoing, true); //接收ssr服务转发来的数据
        
    ctx->stage = tunnel_stage_streaming;
}

static void tunnel_totovpn_client_streaming(struct tunnel_ctx* tunnel, struct socket_ctx* socket) {
    struct socket_ctx* current_socket = socket;
    struct socket_ctx* target_socket = NULL;
    size_t len = 0;
    uint8_t* buf = NULL;
    
    struct client_ctx* ctx = (struct client_ctx*)tunnel->data;
    ASSERT(socket->rdstate == socket_state_done || socket->wrstate == socket_state_done);
    
    if (socket->wrstate == socket_state_done) {
        socket->wrstate = socket_state_stop;
        return; // just return without doing anything.
    } else if (socket->rdstate == socket_state_done) {
        socket->rdstate = socket_state_stop;
    } else {
        UNREACHABLE();
    }

    ASSERT(current_socket == tunnel->incoming || current_socket == tunnel->outgoing);
    
    if (tunnel->is_ws_protocol){
        printf("http.data:%zu\n",(size_t)socket->result);
    }
    else if (tunnel->is_tls_protocol) {
        if (current_socket == tunnel->incoming) {//实测没有收后续的incoming数据
// 加密转发给服务节点,
            struct buffer_t* rec_Data = buffer_create_from((uint8_t*)socket->buf->base, (size_t)socket->buf->len);
//加密、组装后续web请求包
            const uint8_t *out_data=buffer_get_data(rec_Data);
            size_t out_data_len=buffer_get_length(rec_Data);
            size_t back_len=0;
            uint8_t *back_data=hl_totovpn_encrypt_remote_data(tunnel->outbound,out_data,out_data_len,&back_len);
            buffer_release(rec_Data);
            
            if (back_data==NULL) {
                tunnel->tunnel_shutdown(tunnel);
                return;
            }
            
            struct buffer_t *buf=buffer_create_from(back_data, back_len);
            size_t ilen=ss_obfs_tls_req_package(buf,tunnel->ss_obfs);
    // 发送首个web请求数据包
            const uint8_t* encode_data=buffer_get_data(buf);
            tunnel_socket_ctx_write(tunnel, tunnel->outgoing, encode_data, ilen);
//            printf("ss_write_to_remote>%zu\n",ilen);//有>2048的情况
            buffer_release(buf);

        }
        else{
////      收到节点响应数据， 解析、解密转发给socks_5客户端
//关键是这里，服务发来的数据包大小，最大为16384，
            buffer_concatenate_raw(ctx->server_delivery_cache, (uint8_t*)socket->buf->base, (size_t)socket->buf->len);
            size_t decode_len=0;
            int iResult=ss_obfs_tls_rsp_package(ctx->server_delivery_cache,tunnel->ss_obfs,&decode_len);
            if (OBFS_TLS_ERROR==iResult) {
                buffer_shortened_to(ctx->server_delivery_cache, buffer_get_length(ctx->server_delivery_cache), 0, true); //清空数据
                tunnel->tunnel_shutdown(tunnel);
                return;
            }
            else if (decode_len>0) {
                const uint8_t *buf_data=buffer_get_data(ctx->server_delivery_cache);
                size_t buf_len=buffer_get_length(ctx->server_delivery_cache);
                assert(buf_len>=decode_len);
                
                buffer_concatenate_raw(ctx->local_write_cache, buf_data, decode_len); //解析成功(长度decode_len)的数据加到解密缓存
                
                const uint8_t *encrypt_data=buffer_get_data(ctx->local_write_cache);
                size_t encrypt_len=buffer_get_length(ctx->local_write_cache);
                size_t olen=0,decrypt_len=0;
                if (!hl_totovpn_decrypt_local_data(tunnel->outbound,encrypt_data,encrypt_len,&olen,&decrypt_len)){
                    buffer_shortened_to(ctx->server_delivery_cache, buf_len, 0, true); //清空数据
                    buffer_shortened_to(ctx->local_write_cache, encrypt_len, 0, true); //清空数据
                    tunnel->tunnel_shutdown(tunnel);
                    return;
                }
                else{
                    buffer_shortened_to(ctx->server_delivery_cache, decode_len, buf_len-decode_len, true);
//只要是解析出的完整数据不管有否解密成功都要清掉，未解密成功的数据(一般是payloadlen偏大的数据)，缓存起来留待更多数据一起解密
                }
                if (encrypt_len==decrypt_len) {
//解析数据刚好完全解密，则清掉解密缓存
                    buffer_shortened_to(ctx->local_write_cache, encrypt_len, 0, true); //清空数据
                }
                else{ //部分解密成功，或长度不足留待下一次数据；，则要将已成功解密的数据从解密缓存中去掉
// 会有decode_len=16384，decrypt_len=18的情况，解密的时候发现剩余len没有plen大，数据长度不够，此时需加回17 03 03以便下一次解密
                    if (decrypt_len>0) {
//表示已有发送过完整数据，需将已发送的数据cut掉
                        buffer_shortened_to(ctx->local_write_cache, decrypt_len, encrypt_len-decrypt_len, true);
                    }
                }
                
            }
            
        }
    }
    else{//ss-tcp
        target_socket = ((current_socket == tunnel->incoming) ? tunnel->outgoing : tunnel->incoming);
    //如果incoming发来的数据，则target_socket为为outgoing，反之
        ASSERT(tunnel->tunnel_extract_data);
        buf = tunnel->tunnel_extract_data(tunnel, current_socket, &malloc, &len);//得到加密/解密后的数据，再转发给server或local
        if (buf /* && len > 0 */) {
            tunnel_socket_ctx_write(tunnel, target_socket, buf, len);
//            printf("[ss-tcp]wirte2Extra%zu\n",len);
        } else {
            tunnel->tunnel_shutdown(tunnel);
        }
        free(buf);
    }

}

static void totovpn_init_outbound(struct tunnel_ctx* tunnel,const uint8_t* data,size_t size){
    struct client_ctx* ctx = (struct client_ctx*)tunnel->data;
    struct server_env_t* env = ctx->env;
    struct server_config* config = env->config;
    if (tunnel->is_ws_protocol || tunnel->is_tls_protocol){
        tunnel->outbound = hl_session_outbound_new();
        toto_session_outbound_t *ptr=tunnel->outbound;
        
        ptr->tunnel=tunnel;
        ptr->outbound_socket_ctx_write_fn = &totovpn_socket_write_data;
        ptr->server_config=hl_config_parse_servers(config); //初始化vmess配置，特殊处理password等

    //  ss支持以下4种：AES_128_CFB,AEAD_AES_128_GCM,AEAD_AES_256_GCM,AEAD_CHACHA20_POLY1305
        toto_cryptor_type_t cipherType=AES_128_CFB;
        if (strcmp(config->method, "chacha20-ietf-poly1305")==0) {
            cipherType=AEAD_CHACHA20_POLY1305;
        }else if (strcmp(config->method, "aes-128-gcm")==0) {
            cipherType=AEAD_AES_128_GCM;
        }else if (strcmp(config->method, "aes-256-gcm")==0) {
            cipherType=AEAD_AES_256_GCM;
        }
        else if (strcmp(config->method, "aes-128-cfb")==0) {
            cipherType=AES_128_CFB;
        }else{
            cipherType=AEAD_AES_128_GCM; //auto，或不支持的，默认为AEAD_AES_128_GCM
        }
//data为cmd，与init_pk完全一致
//其格式为，如果是domain，则是[type(1)][domainLen(1)][domain(n)][port(2)]，
//       如果ip地址，则是，[type(1)][addr(sizeof(struct))][port(2)]，
        ptr->ctx = hl_outbound_ctx_ss_new(data, size,ptr->server_config->password,strlen(config->password), cipherType);
        //创建ss上下文,data为socks5认证请求数据(内有destAddr+destPort)
    }
}

static void totovpn_init_obfs(struct tunnel_ctx* tunnel,bool is_tls){
    struct client_ctx* ctx = (struct client_ctx*)tunnel->data;
    struct server_env_t* env = ctx->env;
    struct server_config* config = env->config;
    
    tunnel->ss_obfs= (ss_obfs_stage_t *)calloc(1, sizeof(ss_obfs_stage_t));
    size_t iLen=strlen(config->obfs_param);
    tunnel->ss_obfs->host=malloc(iLen+1);
    memcpy(tunnel->ss_obfs->host, config->obfs_param, iLen); //ss协议时obfs_param为obfs-host参数
    tunnel->ss_obfs->host[iLen]='\0';
    
    
//    tunnel->ss_obfs_para = (obfs_para_t *)ss_malloc(sizeof(obfs_para_t));
//    obfs_para_t *ss_obfs_para=tunnel->ss_obfs_para;
//    if (ss_obfs_para) {
//        tunnel->ss_obfs= (ss_obfs_t *)ss_malloc(sizeof(ss_obfs_t));
//        memset(tunnel->ss_obfs, 0, sizeof(ss_obfs_t));
//    }
//
//    ss_obfs_para =is_tls ? obfs_tls : obfs_http;
//
//    struct client_ctx* ctx = (struct client_ctx*)tunnel->data;
//    struct server_env_t* env = ctx->env;
//    struct server_config* config = env->config;
//
//    ss_obfs_para->host = config->obfs_param;
//    if (ss_obfs_para->host==NULL || 0==strlen(ss_obfs_para->host)) {
//        ss_obfs_para->host = "cloudfront.net";
//    }
//    ss_obfs_para->port = config->remote_port;
//    ss_obfs_para->uri = "/";
//    ss_obfs_para->method = "GET";
//    ss_obfs_para->ss_back_response_data=&totovpn_get_ss_response;
//
//    tunnel->ss_obfs_para=ss_obfs_para;
//    ss_obfs_para->tunnel=tunnel;
    
}

static void totovpn_free_obfs(struct tunnel_ctx* tunnel){
    if (tunnel && tunnel->ss_obfs) {
        if (tunnel->ss_obfs->host) {
            free(tunnel->ss_obfs->host);
            tunnel->ss_obfs->host=NULL;
        }
    }
}

static void totovpn_decoded_rep_data_cb(struct buffer_t* buf,void* tunnel_hd){
//    完整的数据包或iv头，进行解密，然后发给客户端
    struct tunnel_ctx* tunnel=(struct tunnel_ctx*)tunnel_hd;
    if (tunnel) {
        size_t olen = 0, clen = 0;
        const uint8_t *out_data=buffer_get_data(buf);
        size_t out_len=buffer_get_length(buf);
        hl_totovpn_decrypt_local_data(tunnel->outbound,out_data,out_len,&olen,&clen); //解密并回调totovpn_socket_write_data发送给客户端
    }else{
        printf("!!!!totovpn_decoded_rep_data_cb>err-tunnel\n");
    }
   
}

static void totovpn_socket_write_data(toto_session_outbound_t* outbound, const void* data, size_t len,bool is2Local){
    struct tunnel_ctx* tunnel=(struct tunnel_ctx*)outbound->tunnel;
    if (!tunnel) {
        printf("!!!!totovpn_decoded_rep_data_cb>err-tunnel\n");
        return;
    }
    if (is2Local) {
////服务节发来的数据经过tls解析，然后解密后，转发给webclient
////数据一般为0x14(改密码)\0x15(警告)\0x16(握手)\0x7(数据)+0x03+0x03开头进行tls相关的操作
//// 数据基本都是以16 03 03开头(HANDSHAKE)，或者17 03 03开头(APPLICATION_DATA)
//// 从这些数据与17 03 03开始。这可能是TLS记录的开始，即0x17（23）是application_data内容类型，0x0303是TLS版本（TLS 1.2）。
        totovpn_socket_write_5000_data(tunnel, tunnel->incoming,data,len);
//        tunnel_socket_ctx_write(tunnel, incoming, data, len);
//        printf("[ss]wirte2Local>%zu\n",len);
        
    }else{
        struct socket_ctx* outgoing = tunnel->outgoing;
        tunnel_socket_ctx_write(tunnel, outgoing, data, len);
//        printf("[ss]wirte2Remote>%zu\n",len);
    }
    
}

//#define SOCKS5_BUFFER_SIZE 4999
static void totovpn_socket_write_5000_data(struct tunnel_ctx* tunnel,struct socket_ctx* incoming,const uint8_t *data,size_t len){
    size_t offset=0;
    size_t left_len=len;
    while (left_len>0) {
//以最大2048大小发送给local
        if (left_len>=4999) {
//            uint8_t tmpBuf[SOCKS5_BUFFER_SIZE+1];
//            memcpy(tmpBuf, data+offset, SOCKS5_BUFFER_SIZE);
//            tmpBuf[SOCKS5_BUFFER_SIZE]='\0';
            tunnel_socket_ctx_write(tunnel, incoming, data+offset, 4999);
            left_len-=4999;
            offset+=4999;
//                printf("[ss]wirte2Local>4999\n");
        }else{
//            uint8_t tmpBuf[SOCKS5_BUFFER_SIZE];
//            memcpy(tmpBuf, data+offset, left_len);
//            tmpBuf[left_len]='\0';
            tunnel_socket_ctx_write(tunnel, incoming, data+offset, left_len);
//                printf("[ss]wirte2Local>%zu\n",len);
            left_len=0;
        }
    }
}
