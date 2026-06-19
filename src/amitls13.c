#include <exec/types.h>
#include <exec/memory.h>
#include <proto/exec.h>
#include <libraries/dos.h>
#include <proto/dos.h>
#include <string.h>
#include <bearssl.h>
#include "amitls13.h"
#include "http_url.h"
#include "socket_os13.h"
#include "x509_insecure.h"

struct AmiTLS13Context {
    LONG fd;
    LONG last_error;
    ULONG flags;
    UBYTE tls_active;
    br_ssl_client_context sc;
    br_sslio_context ioc;
    AmiTLS13InsecureX509Context ix;
    UBYTE iobuf[BR_SSL_BUFSIZE_BIDI];
};

static int tls_sock_read(void *opaque, unsigned char *buf, size_t len)
{
    struct AmiTLS13Context *ctx;
    LONG r;
    ctx=(struct AmiTLS13Context *)opaque;
    r=amitls13_tcp_recv(ctx->fd, buf, (ULONG)len);
    if(r<=0) return -1;
    return (int)r;
}

static int tls_sock_write(void *opaque, const unsigned char *buf, size_t len)
{
    struct AmiTLS13Context *ctx;
    LONG r;
    ctx=(struct AmiTLS13Context *)opaque;
    r=amitls13_tcp_send(ctx->fd, buf, (ULONG)len);
    if(r<=0) return -1;
    return (int)r;
}

static LONG tls_start(struct AmiTLS13Context *ctx, const char *host)
{
    br_ssl_client_zero(&ctx->sc);
    amitls13_x509_insecure_init(&ctx->ix);
    br_ssl_engine_set_x509(&ctx->sc.eng, &ctx->ix.vtable);
    br_ssl_client_set_default_rsapub(&ctx->sc);
    br_ssl_engine_set_versions(&ctx->sc.eng, BR_TLS10, BR_TLS12);
    br_ssl_engine_set_default_aes_cbc(&ctx->sc.eng);
    br_ssl_engine_set_default_aes_gcm(&ctx->sc.eng);
    br_ssl_engine_set_default_des_cbc(&ctx->sc.eng);
    br_ssl_engine_set_default_chapol(&ctx->sc.eng);
    br_ssl_engine_set_default_rsavrfy(&ctx->sc.eng);
    br_ssl_engine_set_default_ecdsa(&ctx->sc.eng);
    br_ssl_engine_set_default_ec(&ctx->sc.eng);
    br_ssl_engine_set_prf10(&ctx->sc.eng, &br_tls10_prf);
    br_ssl_engine_set_prf_sha256(&ctx->sc.eng, &br_tls12_sha256_prf);
    br_ssl_engine_set_prf_sha384(&ctx->sc.eng, &br_tls12_sha384_prf);
    br_ssl_engine_set_buffer(&ctx->sc.eng, ctx->iobuf, sizeof(ctx->iobuf), 1);
    if(!br_ssl_client_reset(&ctx->sc, host, 0)){
        ctx->last_error=AMITLS13_ERR_TLS_DISABLED;
        return AMITLS13_ERR_TLS_DISABLED;
    }
    br_sslio_init(&ctx->ioc, &ctx->sc.eng, tls_sock_read, ctx, tls_sock_write, ctx);
    ctx->tls_active=1;
    return AMITLS13_OK;
}

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

    ctx=(struct AmiTLS13Context *)AllocMem(sizeof(*ctx), MEMF_PUBLIC|MEMF_CLEAR);
    if(!ctx) return 0;
    ctx->fd=-1;
    ctx->flags=flags;

    rc=amitls13_tcp_connect(host, port, &fd);
    if(rc!=AMITLS13_OK){
        ctx->last_error=rc;
        FreeMem(ctx, sizeof(*ctx));
        return 0;
    }

    ctx->fd=fd;
    ctx->last_error=AMITLS13_OK;
    return ctx;
}

LONG AmiTLS13_Write(struct AmiTLS13Context *ctx, const UBYTE *buf, ULONG len)
{
    int r;
    if(!ctx || ctx->fd<0) return AMITLS13_ERR_IO;
    if(ctx->tls_active){
        r=br_sslio_write_all(&ctx->ioc, buf, (size_t)len);
        if(r<0){ ctx->last_error=br_ssl_engine_last_error(&ctx->sc.eng); return AMITLS13_ERR_IO; }
        r=br_sslio_flush(&ctx->ioc);
        if(r<0){ ctx->last_error=br_ssl_engine_last_error(&ctx->sc.eng); return AMITLS13_ERR_IO; }
        return (LONG)len;
    }
    return amitls13_tcp_send(ctx->fd, buf, len);
}

LONG AmiTLS13_Read(struct AmiTLS13Context *ctx, UBYTE *buf, ULONG maxlen)
{
    int r;
    if(!ctx || ctx->fd<0) return AMITLS13_ERR_IO;
    if(ctx->tls_active){
        r=br_sslio_read(&ctx->ioc, buf, (size_t)maxlen);
        if(r<0){ ctx->last_error=br_ssl_engine_last_error(&ctx->sc.eng); return AMITLS13_ERR_IO; }
        return (LONG)r;
    }
    return amitls13_tcp_recv(ctx->fd, buf, maxlen);
}

void AmiTLS13_Close(struct AmiTLS13Context *ctx)
{
    if(!ctx) return;
    if(ctx->tls_active) br_sslio_close(&ctx->ioc);
    if(ctx->fd>=0) amitls13_tcp_close(ctx->fd);
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
    LONG rc;

    if(amitls13_parse_url(url, &parsed)!=AMITLS13_OK) return AMITLS13_ERR_URL;

    ctx=AmiTLS13_Connect(parsed.host, parsed.port, flags);
    if(!ctx) return AMITLS13_ERR_CONNECT;

    if(parsed.https){
        rc=tls_start(ctx, parsed.host);
        if(rc!=AMITLS13_OK){
            AmiTLS13_Close(ctx);
            return rc;
        }
    }

    strcpy(req, "GET ");
    strcat(req, parsed.path);
    strcat(req, " HTTP/1.0\r\nHost: ");
    strcat(req, parsed.host);
    strcat(req, "\r\nConnection: close\r\n\r\n");
    if(AmiTLS13_Write(ctx, (const UBYTE *)req, strlen(req))<0){
        AmiTLS13_Close(ctx);
        return AMITLS13_ERR_IO;
    }

    fh=0;
    if(outfile && outfile[0]) fh=Open((STRPTR)outfile, MODE_NEWFILE);
    total=0;
    while((n=AmiTLS13_Read(ctx, buf, sizeof(buf)))>0){
        total+=n;
        if(fh) Write(fh, buf, n);
    }
    if(fh) Close(fh);
    AmiTLS13_Close(ctx);
    return total;
}
