#include "vmess_ssl_pro.h"
# include <sys/select.h>
static totoVmess_plist_st *totoVmess_plist_snew(void);
static void session_cache_free(totoVmess_ssl_sessions_cache_t *);
static totoVmess_ssl_sessions_cache_t *session_cache_new(const char *sni);
static toto_ssl_ctx_t *toto_ssl_ctx_new(bool ssl_verify,const char *ssl_crt,const char *sni);
static SSL_SESSION *get_session_from_cache(const char *sni);
totoVmess_plist_st *SESSION_CACHE_LIST = NULL;
static totoVmess_list_node_t *totoVmess_plist_sadd(totoVmess_plist_st *ptr, totoVmess_list_node_t *node);
static totoVmess_list_node_t *totoVmess_list_node_new(void *val);
static void totoVmess_plist_sfree(totoVmess_plist_st *ptr);
static void totoVmess_plist_sdel(totoVmess_plist_st *ptr, totoVmess_list_node_t *node);
static int new_session_cb(SSL *ssl, SSL_SESSION *session);
static void remove_session_cb(SSL_CTX *_, SSL_SESSION *session);
static void totoVmess_plist_sdel_val(totoVmess_plist_st *ptr, void *val);
int hl_outbound_ssl_init(toto_session_outbound_t *outbound,int fd)
{
    const char *sni=NULL;
    const char *ssl_crt=NULL;
    bool ssl_verify=false;
    if (0==strcasecmp(outbound->server_config->server_type, "vmess")) {
        toto_config_extra_v2ray_t *ptr=(toto_config_extra_v2ray_t *)outbound->server_config->extra;
        sni=ptr->ssl.sni;
        ssl_crt=ptr->ssl.ssl_crt;
        ssl_verify=ptr->ssl.ssl_verify;
    }
    else if (0==strcasecmp(outbound->server_config->server_type, "shadowsocks")){
        toto_config_extra_ss_t *ptr=(toto_config_extra_ss_t *)outbound->server_config->extra;
        sni=ptr->obfs_host;
        ssl_verify=ptr->ssl_verify;
        ssl_crt=ptr->ssl_crt;
    }
    SSL *ssl = NULL;
    outbound->ssl_ctx = toto_ssl_ctx_new(ssl_verify,ssl_crt,sni);
    if ((ssl = SSL_new(outbound->ssl_ctx->_))){
        if (sni!=NULL) {
            SSL_set_tlsext_host_name(ssl,sni); 
        }
    }
    if (ssl == NULL) {
        return -1;
    }
    SSL_SESSION *session = get_session_from_cache(sni);
    if (session != NULL) {
        SSL_set_session(ssl, session);
    }
   int ret = SSL_set_fd(ssl,fd); 
    if (!ret) {
        printf("!!!SSL_set_fd-fail: %d\n",fd);
        return -1;
    }
    ret=SSL_connect(ssl); 
        while (ret<=0){
           fd_set fds;
           FD_ZERO(&fds);
           FD_SET(fd, &fds);
            int ierr=SSL_get_error(ssl,ret);
            switch (ierr)
            {
               case SSL_ERROR_WANT_READ: 
                   select(fd + 1, &fds, NULL, NULL, NULL); 
                   break;
               case SSL_ERROR_WANT_WRITE:
                   select(fd + 1, NULL, &fds, NULL, NULL);
                   break;
                case SSL_ERROR_WANT_CLIENT_HELLO_CB:
                    select(fd + 1, NULL, &fds, NULL, NULL);;
                    break;
                case SSL_ERROR_SYSCALL://重连全是此错误
                    select(fd + 1, NULL, &fds, NULL, NULL);
                    break;
               default: abort();
            }
            ret = SSL_connect(ssl);
        }
    return 0;
}
static totoVmess_plist_st *totoVmess_plist_snew()
{
    totoVmess_plist_st *ptr = malloc(sizeof(totoVmess_plist_st));
    ptr->head = NULL;
    ptr->tail = NULL;
    ptr->free = NULL;
    ptr->len = 0;
    return ptr;
}
static toto_ssl_ctx_t *toto_ssl_ctx_new(bool ssl_verify,const char *ssl_crt,const char *sni)
{
    toto_ssl_ctx_t *ptr = malloc(sizeof(toto_ssl_ctx_t));
    ptr->_ = NULL;
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL); 
    if ((ptr->_ = SSL_CTX_new(SSLv23_client_method()))) { 
        if (!ssl_verify) {
            SSL_CTX_set_verify(ptr->_, SSL_VERIFY_NONE, NULL);  
        } else {
            SSL_CTX_set_verify(ptr->_, SSL_VERIFY_PEER, NULL);
            bool cert_loaded = false;
            if (ssl_crt != NULL) {
                if (SSL_CTX_load_verify_locations(ptr->_, ssl_crt, NULL) !=1) {
                    printf("!!!Failed to load cert: %s \n",  ssl_crt);
                } else {
                    printf("cert-loaded-OK: %s\n",ssl_crt);
                    cert_loaded = true;
                }
            }
            if (!cert_loaded) {
                X509_STORE *store =SSL_CTX_get_cert_store(ptr->_);
                if (X509_STORE_set_default_paths(store) != 1) {
                    printf("!!!Failed to load system default cert, set verify mode to SSL_VERIFY_NONE now.\n");
                    SSL_CTX_set_verify(ptr->_, SSL_VERIFY_NONE, NULL);
                } else {
                    printf("system cert loaded success!!!");
                }
            }
        }
        SSL_CTX_set_mode(ptr->_, SSL_MODE_AUTO_RETRY); 
        SSL_CTX_set_session_cache_mode(ptr->_, SSL_SESS_CACHE_OFF);
        if (SESSION_CACHE_LIST == NULL) {
            SESSION_CACHE_LIST = totoVmess_plist_snew();
            SESSION_CACHE_LIST->free = (void *)session_cache_free;
            totoVmess_ssl_sessions_cache_t *cache = NULL;
                cache = session_cache_new(sni);
            if (cache != NULL) {
                totoVmess_plist_sadd(SESSION_CACHE_LIST,totoVmess_list_node_new(cache));
            }
        }
        SSL_CTX_set_session_cache_mode(ptr->_, SSL_SESS_CACHE_CLIENT);
        SSL_CTX_sess_set_new_cb(ptr->_, new_session_cb); 
        SSL_CTX_sess_set_remove_cb(ptr->_, remove_session_cb);
    }
    return ptr;
}
void hl_ssl_ctx_free(toto_ssl_ctx_t *ssl_ctx)
{
    if (ssl_ctx) {
        SSL_CTX_free(ssl_ctx->_);
        free(ssl_ctx);
        if (SESSION_CACHE_LIST != NULL) {
            totoVmess_plist_sfree(SESSION_CACHE_LIST);
            SESSION_CACHE_LIST = NULL;
        }
    }
}
static void session_cache_free(totoVmess_ssl_sessions_cache_t *ptr)
{
    if (ptr != NULL) {
        pthread_mutex_destroy(&ptr->lock);
        totoVmess_plist_sfree(ptr->ssl_sessions);
        free(ptr);
        ptr = NULL;
    }
}
static SSL_SESSION *get_session_from_cache(const char *sni)
{
    SSL_SESSION *session = NULL;
    if (SESSION_CACHE_LIST == NULL)
        return NULL;
    if (sni == NULL)
        return NULL;
    totoVmess_list_node_t *cur = NULL, *next = NULL;
    totoVmess_ssl_sessions_cache_t *cache = NULL;
    totoVmess_plist_sforeach(SESSION_CACHE_LIST, cur, next)
    {
        cache = (totoVmess_ssl_sessions_cache_t *)(cur->val);
        if (strcmp(cache->sni, sni) == 0) {
            break;
        }
    }
    if (cache != NULL) {
        pthread_mutex_lock(&cache->lock);
        if (cache->ssl_sessions->len > 0) {
            session = cache->ssl_sessions->head->val;
        }
        pthread_mutex_unlock(&cache->lock);
    }
    return session;
}
static totoVmess_ssl_sessions_cache_t *session_cache_new(const char *sni)
{
    totoVmess_ssl_sessions_cache_t *ptr =
        malloc(sizeof(totoVmess_ssl_sessions_cache_t));
    ptr->ssl_sessions = totoVmess_plist_snew();
    if (pthread_mutex_init(&ptr->lock, NULL) != 0) {
        goto error;
    }
    ptr->sni = sni;
    return ptr;
error:
    session_cache_free(ptr);
    return NULL;
}
static totoVmess_list_node_t *totoVmess_plist_sadd(totoVmess_plist_st *ptr, totoVmess_list_node_t *node)
{
    if (!node)
        return NULL;
    if (ptr->len) {
        node->prev = ptr->tail;
        node->next = NULL;
        ptr->tail->next = node;
        ptr->tail = node;
    } else {
        ptr->head = node;
        ptr->tail = node;
        node->prev = NULL;
        node->next = NULL;
    }
    ++ptr->len;
    return node;
}
static totoVmess_list_node_t *totoVmess_list_node_new(void *val)
{
    totoVmess_list_node_t *ptr = malloc(sizeof(totoVmess_list_node_t));
    ptr->prev = NULL;
    ptr->next = NULL;
    ptr->val = val;
    return ptr;
}
static void totoVmess_plist_sfree(totoVmess_plist_st *ptr)
{
    while (ptr->len) {
        totoVmess_plist_sdel(ptr, ptr->head);
    }
    free(ptr);
}
static void totoVmess_plist_sdel(totoVmess_plist_st *ptr, totoVmess_list_node_t *node)
{
    if (node->prev) {
        node->prev->next = node->next;
    } else {
        ptr->head = node->next;
    }
    if (node->next) {
        node->next->prev = node->prev;
    } else {
        ptr->tail = node->prev;
    }
    if (ptr->free)
        ptr->free(node->val);
    free(node);
    --ptr->len;
}
static int new_session_cb(SSL *ssl, SSL_SESSION *session)
{
    if (SESSION_CACHE_LIST == NULL)
        return 0;
    const char *sni = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (sni != NULL) {
        totoVmess_list_node_t *cur = NULL, *next = NULL;
        totoVmess_ssl_sessions_cache_t *cache = NULL;
        totoVmess_plist_sforeach(SESSION_CACHE_LIST, cur, next)
        {
            cache = (totoVmess_ssl_sessions_cache_t *)(cur->val);
            if (strcmp(cache->sni, sni) == 0) {
                break;
            }
        }
        if (cache != NULL) {
            pthread_mutex_lock(&cache->lock);
            totoVmess_plist_sadd(cache->ssl_sessions,
                     totoVmess_list_node_new(session));
            pthread_mutex_unlock(&cache->lock);
        }
    }
    return 0;
}
static void remove_session_cb(SSL_CTX *_, SSL_SESSION *session)
{
    if (SESSION_CACHE_LIST == NULL)
        return;
    totoVmess_list_node_t *cur = NULL, *next = NULL;
    totoVmess_ssl_sessions_cache_t *cache = NULL;
    bool found = false;
    totoVmess_plist_sforeach(SESSION_CACHE_LIST, cur, next)
    {
        cache = (totoVmess_ssl_sessions_cache_t *)(cur->val);
        totoVmess_list_node_t *scur = NULL, *snext = NULL;
        totoVmess_plist_sforeach(cache->ssl_sessions, scur, snext)
        {
            if (scur->val == session) {
                found = true;
                break;
            }
        }
        if (found) {
            break;
        }
    }
    if (cache != NULL && found) {
        pthread_mutex_lock(&cache->lock);
        totoVmess_plist_sdel_val(cache->ssl_sessions, session);
        pthread_mutex_unlock(&cache->lock);
    }
}
static void totoVmess_plist_sdel_val(totoVmess_plist_st *ptr, void *val)
{
    totoVmess_list_node_t *cur = NULL, *next = NULL;
    totoVmess_plist_sforeach(ptr, cur, next)
    {
        if (cur->val == val)
            break;
    }
    if (cur != NULL)
        totoVmess_plist_sdel(ptr, cur);
}
