#ifndef SH_SOCKET_H
#define SH_SOCKET_H

/* 63 (cmd) + 1 (':') + 63 (host) + 1 ('\0') + 81
 */
#define SH_MAXMSG 209
#define SH_MAXMSGLEN 64

#if defined (SH_WITH_CLIENT)
void sh_socket_server_cmd(const char * srvcmd);
#endif

#if defined (SH_WITH_SERVER)


int    sh_socket_open_int (void);
int    sh_socket_remove (void);
char * sh_socket_check(const char * client_name);
int    sh_socket_poll(void);
void   sh_socket_add2reload (const char * clt);

#endif


#endif
