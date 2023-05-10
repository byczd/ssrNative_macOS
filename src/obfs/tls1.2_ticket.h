

#ifndef _OBFS_TLS1_2_TICKET_H
#define _OBFS_TLS1_2_TICKET_H

struct obfs_t * tls12_ticket_auth_new_obfs(void);

//============================= tls1.2_ticket_fastauth ==================================

void * tls12_ticket_fastauth_init_data(void);
struct obfs_t * tls12_ticket_fastauth_new_obfs(void);

#endif // _OBFS_TLS1_2_TICKET_H

