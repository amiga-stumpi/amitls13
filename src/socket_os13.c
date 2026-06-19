#include <exec/types.h>
#include <exec/libraries.h>
#include <proto/exec.h>
#include <string.h>
#include "amitls13.h"
#include "socket_os13.h"

struct Library *SocketBase = 0;
static LONG g_last_errno = 0;

struct hostent {
    char *h_name;
    char **h_aliases;
    short h_addrtype;
    short h_length;
    char **h_addr_list;
};

struct in_addr { ULONG s_addr; };
struct sockaddr { UBYTE sa_len; UBYTE sa_family; char sa_data[14]; };
struct sockaddr_in { UBYTE sin_len; UBYTE sin_family; UWORD sin_port; struct in_addr sin_addr; char sin_zero[8]; };

#define AF_INET 2
#define SOCK_STREAM 1
#define IPPROTO_TCP 6

static UWORD swap16(UWORD v){ return (UWORD)((v << 8) | (v >> 8)); }

static LONG call_socket(LONG domain, LONG type, LONG protocol)
{
    register LONG d0 __asm("d0") = domain;
    register LONG d1 __asm("d1") = type;
    register LONG d2 __asm("d2") = protocol;
    register struct Library *a6 __asm("a6") = SocketBase;
    __asm volatile("jsr a6@(-30:W)" : "+r"(d0) : "r"(d1), "r"(d2), "r"(a6) : "a0", "a1", "cc", "memory");
    return d0;
}

static LONG call_connect(LONG fd, struct sockaddr *addr, LONG len)
{
    register LONG d0 __asm("d0") = fd;
    register struct sockaddr *a0 __asm("a0") = addr;
    register LONG d1 __asm("d1") = len;
    register struct Library *a6 __asm("a6") = SocketBase;
    __asm volatile("jsr a6@(-54:W)" : "+r"(d0) : "r"(a0), "r"(d1), "r"(a6) : "a1", "cc", "memory");
    return d0;
}

static LONG call_send(LONG fd, const UBYTE *buf, ULONG len)
{
    register LONG d0 __asm("d0") = fd;
    register const UBYTE *a0 __asm("a0") = buf;
    register ULONG d1 __asm("d1") = len;
    register LONG d2 __asm("d2") = 0;
    register struct Library *a6 __asm("a6") = SocketBase;
    __asm volatile("jsr a6@(-66:W)" : "+r"(d0) : "r"(a0), "r"(d1), "r"(d2), "r"(a6) : "a1", "cc", "memory");
    return d0;
}

static LONG call_recv(LONG fd, UBYTE *buf, ULONG len)
{
    register LONG d0 __asm("d0") = fd;
    register UBYTE *a0 __asm("a0") = buf;
    register ULONG d1 __asm("d1") = len;
    register LONG d2 __asm("d2") = 0;
    register struct Library *a6 __asm("a6") = SocketBase;
    __asm volatile("jsr a6@(-78:W)" : "+r"(d0) : "r"(a0), "r"(d1), "r"(d2), "r"(a6) : "a1", "cc", "memory");
    return d0;
}

static LONG call_close(LONG fd)
{
    register LONG d0 __asm("d0") = fd;
    register struct Library *a6 __asm("a6") = SocketBase;
    __asm volatile("jsr a6@(-120:W)" : "+r"(d0) : "r"(a6) : "d1", "a0", "a1", "cc", "memory");
    return d0;
}

static LONG call_errno(void)
{
    register LONG d0 __asm("d0");
    register struct Library *a6 __asm("a6") = SocketBase;
    __asm volatile("jsr a6@(-162:W)" : "=r"(d0) : "r"(a6) : "d1", "a0", "a1", "cc", "memory");
    return d0;
}

static struct hostent *call_gethostbyname(const char *name)
{
    register const char *a0 __asm("a0") = name;
    register struct hostent *d0 __asm("d0");
    register struct Library *a6 __asm("a6") = SocketBase;
    __asm volatile("jsr a6@(-210:W)" : "=r"(d0) : "r"(a0), "r"(a6) : "d1", "a1", "cc", "memory");
    return d0;
}

LONG amitls13_socket_init(void)
{
    if(SocketBase) return AMITLS13_OK;
    SocketBase = OpenLibrary((STRPTR)"bsdsocket.library", 4);
    return SocketBase ? AMITLS13_OK : AMITLS13_ERR_NO_SOCKETLIB;
}

void amitls13_socket_exit(void)
{
    if(SocketBase){
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

    memset(&sa, 0, sizeof(sa));
    sa.sin_len = sizeof(sa);
    sa.sin_family = AF_INET;
    sa.sin_port = swap16(port);
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
    LONG r=call_send(fd, buf, len);
    if(r<0) g_last_errno=call_errno();
    return r;
}

LONG amitls13_tcp_recv(LONG fd, UBYTE *buf, ULONG maxlen)
{
    LONG r=call_recv(fd, buf, maxlen);
    if(r<0) g_last_errno=call_errno();
    return r;
}

LONG amitls13_socket_errno(void)
{
    if(SocketBase) g_last_errno=call_errno();
    return g_last_errno;
}

void amitls13_tcp_close(LONG fd)
{
    if(fd >= 0) call_close(fd);
}
