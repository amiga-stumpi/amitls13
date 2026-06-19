#include <exec/types.h>
#include <exec/memory.h>
#include <exec/execbase.h>
#include <exec/tasks.h>
#include <proto/exec.h>
#include <libraries/dos.h>
#include <proto/dos.h>
#include <string.h>
#include <bearssl.h>
#include "amitls13.h"
#include "http_url.h"
#include "socket_os13.h"
#include "x509_insecure.h"

static void dbg(const char *s)
{
#ifdef AMITLS13_DEBUG
    if(s) Write(Output(), (APTR)s, strlen(s));
#else
    (void)s;
#endif
}

static void dbg_num(LONG n)
{
#ifdef AMITLS13_DEBUG
    char b[16];
    char t[14];
    WORD i=0;
    WORD p=0;
    if(n<0){ dbg("-"); n=-n; }
    do{ t[i++]=(char)('0'+(n%10)); n/=10; }while(n && i<13);
    while(i>0) b[p++]=t[--i];
    b[p]=0;
    dbg(b);
#else
    (void)n;
#endif
}

static void dbg_brerr(LONG e)
{
#ifdef AMITLS13_DEBUG
    dbg_num(e);
    if(e >= BR_ERR_RECV_FATAL_ALERT && e < BR_ERR_SEND_FATAL_ALERT){
        dbg(" recv_alert=");
        dbg_num(e - BR_ERR_RECV_FATAL_ALERT);
    } else if(e >= BR_ERR_SEND_FATAL_ALERT){
        dbg(" send_alert=");
        dbg_num(e - BR_ERR_SEND_FATAL_ALERT);
    }
#else
    (void)e;
#endif
}

static void fill_entropy(ULONG *seed)
{
    struct DateStamp ds;
    ULONG i;

    DateStamp(&ds);
    seed[0]=(ULONG)ds.ds_Days;
    seed[1]=(ULONG)ds.ds_Minute;
    seed[2]=(ULONG)ds.ds_Tick;
    seed[3]=(ULONG)FindTask(0);
    seed[4]=(ULONG)SysBase;
    seed[5]=(ULONG)((struct ExecBase *)SysBase)->VBlankFrequency;
    seed[6]=(ULONG)((struct ExecBase *)SysBase)->ex_EClockFrequency;
    seed[7]=(ULONG)((struct ExecBase *)SysBase)->DispCount;
    seed[8]=(ULONG)AvailMem(MEMF_ANY);
    seed[9]=(ULONG)AvailMem(MEMF_CHIP);
    seed[10]=(ULONG)&seed;
    seed[11]=(ULONG)&ds;
    for(i=0;i<12;i++) seed[i]^=(seed[(i+5)%12]<<5)^(seed[(i+7)%12]>>3)^(0x9e3779b9UL+i);
}

struct AmiTLS13Context {
    LONG fd;
    LONG last_error;
    ULONG flags;
    UBYTE tls_active;
    br_ssl_client_context sc;
    br_x509_minimal_context xc;
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
    if(r<=0){
        dbg("TLS cb read failed err="); dbg_num(amitls13_socket_errno()); dbg("\n");
        return -1;
    }
    return (int)r;
}

static int tls_sock_write(void *opaque, const unsigned char *buf, size_t len)
{
    struct AmiTLS13Context *ctx;
    size_t done;
    LONG r;

    ctx=(struct AmiTLS13Context *)opaque;
    dbg("TLS cb write len="); dbg_num((LONG)len); dbg("\n");
    done=0;
    while(done<len){
        r=amitls13_tcp_send(ctx->fd, buf+done, (ULONG)(len-done));
        if(r<=0){
            dbg("TLS cb write failed done="); dbg_num((LONG)done); dbg(" err="); dbg_num(amitls13_socket_errno()); dbg("\n");
            return -1;
        }
        done+=(size_t)r;
    }
    dbg("TLS cb write done="); dbg_num((LONG)done); dbg("\n");
    return (int)done;
}

static LONG tls_start(struct AmiTLS13Context *ctx, const char *host)
{
    static const uint16_t suites[] = {
        BR_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        BR_TLS_RSA_WITH_AES_128_CBC_SHA256,
        BR_TLS_RSA_WITH_AES_128_CBC_SHA
    };
    ULONG seed[12];

    dbg("TLS init full\n");
    br_ssl_client_init_full(&ctx->sc, &ctx->xc, 0, 0);
    dbg("TLS reduce suites\n");
    br_ssl_engine_set_suites(&ctx->sc.eng, suites, sizeof(suites)/sizeof(suites[0]));

    /* Phase 1 validates transport/TLS flow before CA and hostname checks. */
    dbg("TLS x509 insecure init\n");
    amitls13_x509_insecure_init(&ctx->ix);
    br_ssl_engine_set_x509(&ctx->sc.eng, &ctx->ix.vtable);

    dbg("TLS inject entropy\n");
    fill_entropy(seed);
    br_ssl_engine_inject_entropy(&ctx->sc.eng, seed, sizeof(seed));
    memset(seed, 0, sizeof(seed));

    /* BearSSL reset first clears the existing buffers; it requires that
       a buffer was installed at least once before the first reset. */
    dbg("TLS set buffer\n");
    br_ssl_engine_set_buffer(&ctx->sc.eng, ctx->iobuf, sizeof(ctx->iobuf), 1);

    dbg("TLS client reset sni\n");
    if(!br_ssl_client_reset(&ctx->sc, host, 0)){
        ctx->last_error=br_ssl_engine_last_error(&ctx->sc.eng);
        dbg("TLS client reset failed brerr=");
        dbg_brerr(ctx->last_error);
        dbg("\n");
        return AMITLS13_ERR_TLS_DISABLED;
    }
    dbg("TLS sslio init\n");
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
        dbg("TLS write_all begin len="); dbg_num((LONG)len); dbg("\n");
        r=br_sslio_write_all(&ctx->ioc, buf, (size_t)len);
        dbg("TLS write_all ret="); dbg_num((LONG)r); dbg(" brerr="); dbg_brerr(br_ssl_engine_last_error(&ctx->sc.eng)); dbg("\n");
        if(r<0){ ctx->last_error=br_ssl_engine_last_error(&ctx->sc.eng); return AMITLS13_ERR_IO; }
        dbg("TLS flush begin\n");
        r=br_sslio_flush(&ctx->ioc);
        dbg("TLS flush ret="); dbg_num((LONG)r); dbg(" brerr="); dbg_brerr(br_ssl_engine_last_error(&ctx->sc.eng)); dbg("\n");
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
    if(parsed.https) dbg("TLS write request\n");
    if(AmiTLS13_Write(ctx, (const UBYTE *)req, strlen(req))<0){
        AmiTLS13_Close(ctx);
        return AMITLS13_ERR_IO;
    }

    fh=0;
    if(outfile && outfile[0]) fh=Open((STRPTR)outfile, MODE_NEWFILE);
    total=0;
    if(parsed.https) dbg("TLS read response\n");
    while((n=AmiTLS13_Read(ctx, buf, sizeof(buf)))>0){
        total+=n;
        if(fh) Write(fh, buf, n);
    }
    if(fh) Close(fh);
    AmiTLS13_Close(ctx);
    return total;
}
