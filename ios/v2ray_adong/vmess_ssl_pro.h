#ifndef vmess_ssl_pro_h
#define vmess_ssl_pro_h
#include <stdio.h>
#include "vmessTools.h"
typedef struct totoVmess_list_node_s {
    void *val;
    struct totoVmess_list_node_s *prev;
    struct totoVmess_list_node_s *next;
} totoVmess_list_node_t;
typedef struct totoVmess_plist_ss {
    totoVmess_list_node_t *head;
    totoVmess_list_node_t *tail;
    size_t len;
    void (*free)(void *val);
} totoVmess_plist_st;
typedef struct totoVmess_ssl_sessions_cache_s {
    const char *sni;
    totoVmess_plist_st *ssl_sessions;
    pthread_mutex_t lock;
} totoVmess_ssl_sessions_cache_t;
int hl_outbound_ssl_init(toto_session_outbound_t *outbound,int fd);
void hl_ssl_ctx_free(toto_ssl_ctx_t *ssl_ctx);
#define totoVmess_plist_sforeach(list, cur, _next)                                     \
    for ((cur) = (list)->head, (_next) = (cur) ? ((cur)->next) : (NULL);   \
         (cur) != NULL;                                                    \
         (cur) = (_next), (_next) = (cur) ? ((cur)->next) : (NULL))
#endif 
