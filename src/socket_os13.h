#ifndef AMITLS13_SOCKET_OS13_H
#define AMITLS13_SOCKET_OS13_H

#include <exec/types.h>

LONG amitls13_socket_init(void);
void amitls13_socket_exit(void);
LONG amitls13_tcp_connect(const char *host, UWORD port, LONG *out_fd);
LONG amitls13_tcp_send(LONG fd, const UBYTE *buf, ULONG len);
LONG amitls13_tcp_recv(LONG fd, UBYTE *buf, ULONG maxlen);
void amitls13_tcp_close(LONG fd);

#endif
