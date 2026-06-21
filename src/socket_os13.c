#include <exec/types.h>
#include <exec/libraries.h>
#include <proto/exec.h>
#include <string.h>
#include "amitls13.h"
#include "socket_os13.h"

struct Library *SocketBase = 0;
static LONG g_last_errno = 0;
static UWORD g_socket_open_count = 0;

struct hostent {
    char *h_name;
    char **h_aliases;
    int h_addrtype;
    int h_length;
    char **h_addr_list;
};

struct in_addr { ULONG s_addr; };
struct sockaddr { UBYTE sa_len; UBYTE sa_family; char sa_data[14]; };
struct sockaddr_in { UBYTE sin_len; UBYTE sin_family; UWORD sin_port; struct in_addr sin_addr; char sin_zero[8]; };

#define AF_INET 2
#define SOCK_STREAM 1
#define IPPROTO_TCP 6


static void fd_zero(ULONG *fds)
{
    UWORD i;
    for(i=0;i<8;i++) fds[i]=0;
}

static void fd_set_one(ULONG *fds, LONG fd)
{
    if(fd >= 0 && fd < 256) fds[(UWORD)fd >> 5] |= (1UL << ((UWORD)fd & 31));
}


LONG amitls13_bsdsocket_socket(LONG domain, LONG type, LONG protocol);
LONG amitls13_bsdsocket_connect(LONG fd, struct sockaddr *addr, LONG len);
LONG amitls13_bsdsocket_send(LONG fd, const UBYTE *buf, ULONG len);
LONG amitls13_bsdsocket_recv(LONG fd, UBYTE *buf, ULONG len);
LONG amitls13_bsdsocket_close(LONG fd);
LONG amitls13_bsdsocket_waitselect(LONG nfds, ULONG *readfds, ULONG *writefds, ULONG *exceptfds, struct timeval *tv, ULONG *signals);
LONG amitls13_bsdsocket_errno(void);
struct hostent *amitls13_bsdsocket_gethostbyname(const char *name);

static LONG call_socket(LONG domain, LONG type, LONG protocol)
{
    return amitls13_bsdsocket_socket(domain, type, protocol);
}

static LONG call_connect(LONG fd, struct sockaddr *addr, LONG len)
{
    return amitls13_bsdsocket_connect(fd, addr, len);
}

static LONG call_send(LONG fd, const UBYTE *buf, ULONG len)
{
    return amitls13_bsdsocket_send(fd, buf, len);
}

static LONG call_recv(LONG fd, UBYTE *buf, ULONG len)
{
    return amitls13_bsdsocket_recv(fd, buf, len);
}

static LONG call_close(LONG fd)
{
    return amitls13_bsdsocket_close(fd);
}


static LONG call_waitselect(LONG nfds, ULONG *readfds, ULONG *writefds, ULONG *exceptfds, struct timeval *tv, ULONG *signals)
{
    return amitls13_bsdsocket_waitselect(nfds, readfds, writefds, exceptfds, tv, signals);
}

static LONG call_errno(void)
{
    return amitls13_bsdsocket_errno();
}

static struct hostent *call_gethostbyname(const char *name)
{
    return amitls13_bsdsocket_gethostbyname(name);
}

LONG amitls13_socket_init(void)
{
    if(SocketBase){
        g_socket_open_count++;
        return AMITLS13_OK;
    }
    SocketBase = OpenLibrary((STRPTR)"bsdsocket.library", 4);
    if(!SocketBase) return AMITLS13_ERR_NO_SOCKETLIB;
    g_socket_open_count = 1;
    return AMITLS13_OK;
}

void amitls13_socket_exit(void)
{
    if(!SocketBase) return;
    if(g_socket_open_count > 0) g_socket_open_count--;
    if(g_socket_open_count == 0){
        CloseLibrary(SocketBase);
        SocketBase = 0;
    }
}

LONG amitls13_tcp_connect(const char *host, UWORD port, LONG *out_fd)
{
    struct hostent *he;
    struct sockaddr_in sa;
    LONG fd;

    if(!SocketBase) return AMITLS13_ERR_NO_SOCKETLIB;
    if(!host || !out_fd) return AMITLS13_ERR_SOCKET;
    g_last_errno=0;

    he = call_gethostbyname(host);
    if(!he || !he->h_addr_list || !he->h_addr_list[0]){ g_last_errno=call_errno(); return AMITLS13_ERR_DNS; }

    fd = call_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(fd < 0){ g_last_errno=call_errno(); return AMITLS13_ERR_SOCKET; }
    if(fd == 0){
        LONG fd2;
        fd2 = call_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if(fd2 >= 0){
            call_close(fd);
            fd = fd2;
        }
    }

    memset(&sa, 0, sizeof(sa));
    sa.sin_len = sizeof(sa);
    sa.sin_family = AF_INET;
    sa.sin_port = port;
    memcpy(&sa.sin_addr.s_addr, he->h_addr_list[0], 4);

    if(call_connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0){
        g_last_errno=call_errno();
        call_close(fd);
        return AMITLS13_ERR_CONNECT;
    }

    *out_fd = fd;
    g_last_errno=0;
    return AMITLS13_OK;
}

LONG amitls13_tcp_send(LONG fd, const UBYTE *buf, ULONG len)
{
    LONG r;
    g_last_errno=0;
    r=call_send(fd, buf, len);
    if(r<0) g_last_errno=call_errno();
    return r;
}

LONG amitls13_tcp_recv(LONG fd, UBYTE *buf, ULONG maxlen)
{
    LONG r;
    g_last_errno=0;
    r=call_recv(fd, buf, maxlen);
    if(r<0) g_last_errno=call_errno();
    return r;
}

LONG amitls13_tcp_wait_read(LONG fd, ULONG micros)
{
    ULONG rfds[8];
    struct timeval tv;
    LONG r;

    if(!SocketBase || fd < 0) return AMITLS13_ERR_SOCKET;
    fd_zero(rfds);
    fd_set_one(rfds, fd);
    tv.tv_sec = (LONG)(micros / 1000000UL);
    tv.tv_usec = (LONG)(micros % 1000000UL);
    g_last_errno = 0;
    r = call_waitselect(fd + 1, rfds, 0, 0, &tv, 0);
    if(r < 0) g_last_errno = call_errno();
    return r;
}

LONG amitls13_tcp_wait_write(LONG fd, ULONG micros)
{
    ULONG wfds[8];
    struct timeval tv;
    LONG r;

    if(!SocketBase || fd < 0) return AMITLS13_ERR_SOCKET;
    fd_zero(wfds);
    fd_set_one(wfds, fd);
    tv.tv_sec = (LONG)(micros / 1000000UL);
    tv.tv_usec = (LONG)(micros % 1000000UL);
    g_last_errno = 0;
    r = call_waitselect(fd + 1, 0, wfds, 0, &tv, 0);
    if(r < 0) g_last_errno = call_errno();
    return r;
}

LONG amitls13_socket_errno(void)
{
    return g_last_errno;
}

void amitls13_tcp_close(LONG fd)
{
    if(fd >= 0) call_close(fd);
}
