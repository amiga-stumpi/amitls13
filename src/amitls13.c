#include <exec/types.h>
#include <exec/memory.h>
#include <proto/exec.h>
#include <libraries/dos.h>
#include <proto/dos.h>
#include <string.h>
#include "amitls13.h"
#include "http_url.h"
#include "socket_os13.h"

struct AmiTLS13Context {
    LONG fd;
    LONG last_error;
    ULONG flags;
};

LONG AmiTLS13_Init(void)
{
    return amitls13_socket_init();
}

void AmiTLS13_Exit(void)
{
    amitls13_socket_exit();
}

struct AmiTLS13Context *AmiTLS13_Connect(const char *host, UWORD port, ULONG flags)
{
    struct AmiTLS13Context *ctx;
    LONG fd;
    LONG rc;

    ctx = (struct AmiTLS13Context *)AllocMem(sizeof(*ctx), MEMF_PUBLIC|MEMF_CLEAR);
    if(!ctx) return 0;
    ctx->fd = -1;
    ctx->flags = flags;

    rc = amitls13_tcp_connect(host, port, &fd);
    if(rc != AMITLS13_OK){
        ctx->last_error = rc;
        FreeMem(ctx, sizeof(*ctx));
        return 0;
    }

    ctx->fd = fd;
    ctx->last_error = AMITLS13_ERR_TLS_DISABLED;
    return ctx;
}

LONG AmiTLS13_Write(struct AmiTLS13Context *ctx, const UBYTE *buf, ULONG len)
{
    if(!ctx || ctx->fd < 0) return AMITLS13_ERR_IO;
    return amitls13_tcp_send(ctx->fd, buf, len);
}

LONG AmiTLS13_Read(struct AmiTLS13Context *ctx, UBYTE *buf, ULONG maxlen)
{
    if(!ctx || ctx->fd < 0) return AMITLS13_ERR_IO;
    return amitls13_tcp_recv(ctx->fd, buf, maxlen);
}

void AmiTLS13_Close(struct AmiTLS13Context *ctx)
{
    if(!ctx) return;
    if(ctx->fd >= 0) amitls13_tcp_close(ctx->fd);
    FreeMem(ctx, sizeof(*ctx));
}

LONG AmiTLS13_GetLastError(struct AmiTLS13Context *ctx)
{
    return ctx ? ctx->last_error : AMITLS13_ERR_IO;
}

LONG AmiTLS13_HTTPGet(const char *url, const char *outfile, ULONG flags)
{
    AmiTLS13Url parsed;
    struct AmiTLS13Context *ctx;
    BPTR fh;
    char req[420];
    UBYTE buf[1024];
    LONG n;
    LONG total;

    if(amitls13_parse_url(url, &parsed) != AMITLS13_OK) return AMITLS13_ERR_URL;
    if(parsed.https) return AMITLS13_ERR_TLS_DISABLED;

    ctx = AmiTLS13_Connect(parsed.host, parsed.port, flags);
    if(!ctx) return AMITLS13_ERR_CONNECT;

    strcpy(req, "GET ");
    strcat(req, parsed.path);
    strcat(req, " HTTP/1.0\r\nHost: ");
    strcat(req, parsed.host);
    strcat(req, "\r\nConnection: close\r\n\r\n");
    if(AmiTLS13_Write(ctx, (const UBYTE *)req, strlen(req)) < 0){
        AmiTLS13_Close(ctx);
        return AMITLS13_ERR_IO;
    }

    fh = 0;
    if(outfile && outfile[0]) fh = Open((STRPTR)outfile, MODE_NEWFILE);
    total = 0;
    while((n = AmiTLS13_Read(ctx, buf, sizeof(buf))) > 0){
        total += n;
        if(fh) Write(fh, buf, n);
    }
    if(fh) Close(fh);
    AmiTLS13_Close(ctx);
    return total;
}
