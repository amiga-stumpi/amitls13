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

#ifndef AMITLS13_TLS_SEND_CHUNK
#define AMITLS13_TLS_SEND_CHUNK 512UL
#endif
#ifndef AMITLS13_TLS_WAIT_US
#define AMITLS13_TLS_WAIT_US 50000UL
#endif
#ifndef AMITLS13_TLS_IO_TRIES
#define AMITLS13_TLS_IO_TRIES 200
#endif
#ifndef AMITLS13_HTTP_REQ_BUF
#define AMITLS13_HTTP_REQ_BUF 512UL
#endif
#ifndef AMITLS13_HTTP_RECV_BUF
#define AMITLS13_HTTP_RECV_BUF 2048UL
#endif
#ifndef AMITLS13_HOST_COPY_BUF
#define AMITLS13_HOST_COPY_BUF 256UL
#endif
#ifndef AMITLS13_MEM_FLAGS
#define AMITLS13_MEM_FLAGS MEMF_PUBLIC
#endif
#ifndef AMITLS13_MEM_CLEAR_FLAGS
#define AMITLS13_MEM_CLEAR_FLAGS (MEMF_PUBLIC|MEMF_CLEAR)
#endif

static BPTR g_debug_output = 0;
static UBYTE g_pubkey_pin_sha256[32];
static UBYTE g_pubkey_pin_enabled = 0;
static UBYTE g_last_peer_pubkey_sha256[32];
static UBYTE g_last_peer_pubkey_valid = 0;

void AmiTLS13_SetDebugOutput(BPTR fh)
{
    g_debug_output = fh;
}

void AmiTLS13_DebugWrite(const char *s)
{
#ifdef AMITLS13_DEBUG
    BPTR out;
    if(!s) return;
    out = g_debug_output ? g_debug_output : Output();
    Write(out, (APTR)s, strlen(s));
#else
    (void)s;
#endif
}

LONG AmiTLS13_SetPublicKeyPinSHA256(const UBYTE *sha256, ULONG len)
{
    if(!sha256 || len == 0){
        memset(g_pubkey_pin_sha256, 0, sizeof(g_pubkey_pin_sha256));
        g_pubkey_pin_enabled = 0;
        return AMITLS13_OK;
    }
    if(len != 32) return AMITLS13_ERR_CERT_PIN;
    memcpy(g_pubkey_pin_sha256, sha256, 32);
    g_pubkey_pin_enabled = 1;
    return AMITLS13_OK;
}

LONG AmiTLS13_GetLastPeerPublicKeySHA256(UBYTE *out_sha256, ULONG len)
{
    if(!out_sha256 || len < 32 || !g_last_peer_pubkey_valid) return AMITLS13_ERR_CERT_PIN;
    memcpy(out_sha256, g_last_peer_pubkey_sha256, 32);
    return AMITLS13_OK;
}

#ifdef AMITLS13_DEBUG
static void dbg(const char *s)
{
    AmiTLS13_DebugWrite(s);
}

static void dbg_num(LONG n)
{
    char b[16];
    char t[14];
    WORD i=0;
    WORD p=0;
    if(n<0){ dbg("-"); n=-n; }
    do{ t[i++]=(char)('0'+(n%10)); n/=10; }while(n && i<13);
    while(i>0) b[p++]=t[--i];
    b[p]=0;
    dbg(b);
}

static void dbg_hex_byte(UBYTE v)
{
    static const char hx[] = "0123456789ABCDEF";
    char b[3];
    b[0] = hx[(v >> 4) & 15];
    b[1] = hx[v & 15];
    b[2] = 0;
    dbg(b);
}

static void dbg_dump_bytes(const char *prefix, const UBYTE *buf, ULONG len)
{
    ULONG i, n;
    dbg(prefix);
    n = len;
    if(n > 48) n = 48;
    for(i=0;i<n;i++){
        if(i) dbg(" ");
        dbg_hex_byte(buf[i]);
    }
    dbg("\n");
}

static void dbg_brerr(LONG e)
{
    dbg_num(e);
    if(e >= BR_ERR_RECV_FATAL_ALERT && e < BR_ERR_SEND_FATAL_ALERT){
        dbg(" recv_alert=");
        dbg_num(e - BR_ERR_RECV_FATAL_ALERT);
    } else if(e >= BR_ERR_SEND_FATAL_ALERT){
        dbg(" send_alert=");
        dbg_num(e - BR_ERR_SEND_FATAL_ALERT);
    }
}
#else
#define dbg(s) ((void)0)
#define dbg_num(n) ((void)0)
#define dbg_dump_bytes(prefix, buf, len) ((void)0)
#define dbg_brerr(e) ((void)0)
#endif

#ifdef AMITLS13_TRACE
static void trace(const char *s)
{
    if(s) Write(Output(), (APTR)s, strlen(s));
}
#else
#define trace(s) ((void)0)
#endif

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
    UBYTE tls_broken;
    UBYTE suppress_alert_writes;
    br_ssl_client_context sc;
    br_sslio_context ioc;
    AmiTLS13InsecureX509Context ix;
    UBYTE iobuf[BR_SSL_BUFSIZE_BIDI];
};


static int tls_sock_read(void *opaque, unsigned char *buf, size_t len)
{
    struct AmiTLS13Context *ctx;
    LONG fd;
    LONG r;
    trace("TRACE cb read enter\n");
    ctx = (struct AmiTLS13Context *)opaque;
    if(!ctx) return -1;
    fd=ctx->fd;
    trace("TRACE cb read fd\n");
    if(fd < 0) return -1;
    {
        UWORD tries;
        for(tries=0; tries<AMITLS13_TLS_IO_TRIES; tries++){
            r=amitls13_tcp_recv(fd, buf, (ULONG)len);
            if(r>0) return (int)r;
            if(r<0) break;
            if(amitls13_socket_errno()!=0) break;
            {
                LONG wr;
                dbg("TLS cb read empty wait\n");
                wr = amitls13_tcp_wait_read(fd, AMITLS13_TLS_WAIT_US);
                dbg("TLS cb wait ret="); dbg_num(wr); dbg(" err="); dbg_num(amitls13_socket_errno()); dbg("\n");
                if(wr < 0) break;
            }
        }
    }
    dbg("TLS cb read failed ret="); dbg_num(r); dbg(" err="); dbg_num(amitls13_socket_errno()); dbg("\n");
    return -1;
}

static int tls_sock_write(void *opaque, const unsigned char *buf, size_t len)
{
    struct AmiTLS13Context *ctx;
    LONG fd;
    size_t done;
    ULONG chunk;
    LONG r;

    trace("TRACE cb write enter\n");
    ctx = (struct AmiTLS13Context *)opaque;
    if(!ctx) return -1;
    fd=ctx->fd;
    trace("TRACE cb write fd\n");
    if(fd < 0){ trace("TRACE cb write nofd\n"); return -1; }
    trace("TRACE cb write havefd\n");
    dbg("TLS cb write len="); dbg_num((LONG)len); dbg("\n");
    dbg_dump_bytes("TLS cb write bytes=", buf, (ULONG)len);
    if(ctx->suppress_alert_writes && len >= 1 && buf[0] == 0x15){
        dbg("TLS cb write alert suppressed\n");
        return (int)len;
    }
    done=0;
    while(done<len){
        UWORD tries;
        r=0;
        for(tries=0; tries<AMITLS13_TLS_IO_TRIES; tries++){
            chunk = (ULONG)(len - done);
            if(chunk > AMITLS13_TLS_SEND_CHUNK) chunk = AMITLS13_TLS_SEND_CHUNK;
            dbg("TLS cb send begin fd="); dbg_num(fd); dbg(" done="); dbg_num((LONG)done); dbg(" chunk="); dbg_num((LONG)chunk); dbg("\n");
            r=amitls13_tcp_send(fd, buf+done, chunk);
            if(r>0) break;
            dbg("TLS cb write wait done="); dbg_num((LONG)done); dbg(" err="); dbg_num(amitls13_socket_errno()); dbg("\n");
            { LONG wr = amitls13_tcp_wait_write(fd, AMITLS13_TLS_WAIT_US);
              dbg("TLS cb write wait ret="); dbg_num(wr); dbg(" err="); dbg_num(amitls13_socket_errno()); dbg("\n");
              if(wr < 0) break; }
        }
        if(r<=0){
            dbg("TLS cb write failed done="); dbg_num((LONG)done); dbg(" err="); dbg_num(amitls13_socket_errno()); dbg("\n");
            ctx->tls_broken=1;
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
        BR_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    };
    ULONG seed[12];
    char host_copy[256];
    UWORD hi;

    trace("TRACE tls_start enter\n");
    if(!host) return AMITLS13_ERR_URL;
    hi=0;
    while(host[hi] && hi<255){
        host_copy[hi]=host[hi];
        hi++;
    }
    host_copy[hi]=0;
    if(host[hi]) return AMITLS13_ERR_URL;

    trace("TRACE tls init\n");
    dbg("TLS init minimal\n");
    br_ssl_client_zero(&ctx->sc);
    br_ssl_engine_set_versions(&ctx->sc.eng, BR_TLS12, BR_TLS12);
    br_ssl_engine_set_suites(&ctx->sc.eng, suites, sizeof(suites)/sizeof(suites[0]));
    br_ssl_client_set_rsapub(&ctx->sc, br_rsa_i15_public);
    br_ssl_engine_set_rsavrfy(&ctx->sc.eng, br_rsa_i15_pkcs1_vrfy);
    br_ssl_engine_set_ec(&ctx->sc.eng, &br_ec_p256_m15);
    br_ssl_engine_set_hash(&ctx->sc.eng, br_sha1_ID, &br_sha1_vtable);
    br_ssl_engine_set_hash(&ctx->sc.eng, br_sha256_ID, &br_sha256_vtable);
    br_ssl_engine_set_prf_sha256(&ctx->sc.eng, &br_tls12_sha256_prf);
    br_ssl_engine_set_gcm(&ctx->sc.eng, &br_sslrec_in_gcm_vtable, &br_sslrec_out_gcm_vtable);
    br_ssl_engine_set_aes_ctr(&ctx->sc.eng, &br_aes_ct_ctr_vtable);
    br_ssl_engine_set_ghash(&ctx->sc.eng, &br_ghash_ctmul32);

    /* Phase 1 validates transport/TLS flow before CA and hostname checks. */
    dbg("TLS x509 insecure init\n");
    amitls13_x509_insecure_init(&ctx->ix);
    if(g_pubkey_pin_enabled && (ctx->flags & AMITLS13F_PIN_PUBKEY_SHA256))
        amitls13_x509_set_pubkey_pin_sha256(&ctx->ix, g_pubkey_pin_sha256);
    br_ssl_engine_set_x509(&ctx->sc.eng, &ctx->ix.vtable);

    trace("TRACE tls entropy\n");
    dbg("TLS inject entropy\n");
    fill_entropy(seed);
    br_ssl_engine_inject_entropy(&ctx->sc.eng, seed, sizeof(seed));
    memset(seed, 0, sizeof(seed));

    /* BearSSL reset first clears the existing buffers; it requires that
       a buffer was installed at least once before the first reset. */
    dbg("TLS set buffer\n");
    br_ssl_engine_set_buffer(&ctx->sc.eng, ctx->iobuf, sizeof(ctx->iobuf), 1);

    trace("TRACE tls reset\n");
    dbg("TLS client reset sni hostlen="); dbg_num((LONG)hi); dbg("\n");
    if(!br_ssl_client_reset(&ctx->sc, host_copy, 0)){
        ctx->last_error=br_ssl_engine_last_error(&ctx->sc.eng);
        dbg("TLS client reset failed brerr=");
        dbg_brerr(ctx->last_error);
        dbg("\n");
        return AMITLS13_ERR_TLS_DISABLED;
    }
    trace("TRACE tls reset ok\n");
    dbg("TLS reset ok\n");
    dbg("TLS sslio init\n");
    br_sslio_init(&ctx->ioc, &ctx->sc.eng, tls_sock_read, ctx, tls_sock_write, ctx);
    ctx->tls_active=1;
    trace("TRACE tls_start leave\n");
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

    trace("TRACE connect alloc\n");
    ctx=(struct AmiTLS13Context *)AllocMem(sizeof(*ctx), AMITLS13_MEM_CLEAR_FLAGS);
    if(!ctx) return 0;
    fd=-1;
    ctx->flags=flags;

    trace("TRACE tcp connect\n");
    rc=amitls13_tcp_connect(host, port, &fd);
    if(rc!=AMITLS13_OK){
        ctx->last_error=rc;
        FreeMem(ctx, sizeof(*ctx));
        return 0;
    }

    trace("TRACE tcp connected\n");
    ctx->fd=fd;
    ctx->last_error=AMITLS13_OK;
    return ctx;
}

LONG AmiTLS13_Write(struct AmiTLS13Context *ctx, const UBYTE *buf, ULONG len)
{
    int r;
    if(!ctx || ctx->fd<0) return AMITLS13_ERR_IO;
    if(ctx->tls_active){
        trace("TRACE write tls active\n");
        dbg("TLS write_all begin len="); dbg_num((LONG)len); dbg("\n");
        trace("TRACE write_all call\n");
        r=br_sslio_write_all(&ctx->ioc, buf, (size_t)len);
        trace("TRACE write_all ret\n");
        ctx->last_error=br_ssl_engine_last_error(&ctx->sc.eng);
        dbg("TLS write_all ret="); dbg_num((LONG)r); dbg(" brerr="); dbg_brerr(ctx->last_error); dbg("\n");
        if(r!=0 || ctx->last_error!=BR_ERR_OK){ trace("TRACE write_all fail\n"); ctx->tls_broken=1; return AMITLS13_ERR_IO; }
        trace("TRACE flush call\n");
        dbg("TLS flush begin\n");
        r=br_sslio_flush(&ctx->ioc);
        trace("TRACE flush ret\n");
        ctx->last_error=br_ssl_engine_last_error(&ctx->sc.eng);
        dbg("TLS flush ret="); dbg_num((LONG)r); dbg(" brerr="); dbg_brerr(ctx->last_error); dbg("\n");
        if(r!=0 || ctx->last_error!=BR_ERR_OK){ trace("TRACE flush fail\n"); ctx->tls_broken=1; return AMITLS13_ERR_IO; }
        trace("TRACE write ok\n");
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
        if(r<0){ trace("TRACE read fail\n"); ctx->last_error=br_ssl_engine_last_error(&ctx->sc.eng); ctx->tls_broken=1; return AMITLS13_ERR_IO; }
        return (LONG)r;
    }
    return amitls13_tcp_recv(ctx->fd, buf, maxlen);
}

void AmiTLS13_Close(struct AmiTLS13Context *ctx)
{
    if(!ctx) return;
    dbg("AmiTLS13 close tls="); dbg_num((LONG)ctx->tls_active); dbg(" broken="); dbg_num((LONG)ctx->tls_broken); dbg(" last="); dbg_brerr(ctx->last_error); dbg("\n");
    /*
       HTTP/1.0 responses use TCP close as EOF. Some servers have already
       closed their side when BearSSL tries to emit close_notify here; on
       OS1.3 bsdsocket stacks that can turn a successful transfer into a
       send stall during cleanup. For this small client wrapper, closing the
       raw socket after a fully-read response is the safer behaviour.
    */
    if(ctx->fd>=0){
        dbg("AmiTLS13 raw close fd\n");
        amitls13_tcp_close(ctx->fd);
        ctx->fd=-1;
    }
    #ifdef AMITLS13_DEBUG
    if(ctx->tls_broken){ dbg("AmiTLS13 leak broken ctx for diagnosis\n"); return; }
#endif
    dbg("AmiTLS13 free ctx\n");
    FreeMem(ctx, sizeof(*ctx));
}

LONG AmiTLS13_GetLastError(struct AmiTLS13Context *ctx)
{
    return ctx ? ctx->last_error : AMITLS13_ERR_IO;
}

LONG AmiTLS13_SocketErrno(void)
{
    return amitls13_socket_errno();
}

LONG AmiTLS13_HTTPGet(const char *url, const char *outfile, ULONG flags)
{
    AmiTLS13Url parsed;
    struct AmiTLS13Context *ctx;
    BPTR fh;
    char *req;
    UBYTE *buf;
    LONG n;
    LONG total;
    LONG rc;

    ctx = 0;
    fh = 0;
    req = 0;
    buf = 0;
    total = 0;
    g_last_peer_pubkey_valid = 0;

    trace("TRACE httpget parse\n");
    if(amitls13_parse_url(url, &parsed)!=AMITLS13_OK) return AMITLS13_ERR_URL;

    req = (char *)AllocMem(512, AMITLS13_MEM_CLEAR_FLAGS);
    buf = (UBYTE *)AllocMem(1024, AMITLS13_MEM_FLAGS);
    if(!req || !buf){
        rc = AMITLS13_ERR_IO;
        goto cleanup;
    }

    trace("TRACE httpget connect\n");
    ctx=AmiTLS13_Connect(parsed.host, parsed.port, flags);
    if(!ctx){ rc = AMITLS13_ERR_CONNECT; goto cleanup; }

    if(parsed.https){
        trace("TRACE httpget tls\n");
        rc=tls_start(ctx, parsed.host);
        if(rc!=AMITLS13_OK) goto cleanup;
    }

    trace("TRACE httpget request build\n");
    strcpy(req, "GET ");
    strcat(req, parsed.path);
    strcat(req, " HTTP/1.0\r\nHost: ");
    strcat(req, parsed.host);
    strcat(req, "\r\nConnection: close\r\n\r\n");
    if(parsed.https) dbg("TLS write request\n");
    trace("TRACE httpget write\n");
    if(AmiTLS13_Write(ctx, (const UBYTE *)req, strlen(req))<0){
        rc = AMITLS13_ERR_IO;
        goto cleanup;
    }

    trace("TRACE httpget open out\n");
    if(outfile && outfile[0]) fh=Open((STRPTR)outfile, MODE_NEWFILE);
    if(parsed.https){
        dbg("TLS read response\n");
        ctx->suppress_alert_writes = 1;
    }
    trace("TRACE httpget read loop\n");
    while((n=AmiTLS13_Read(ctx, buf, 1024))>0){
        total+=n;
        if(fh) Write(fh, buf, n);
    }
    trace("TRACE httpget read done\n");
    if(ctx && ctx->tls_active && ctx->ix.have_pkey){
        memcpy(g_last_peer_pubkey_sha256, ctx->ix.leaf_key_sha256, 32);
        g_last_peer_pubkey_valid = 1;
    }
    rc = total;

cleanup:
    if(fh) Close(fh);
    if(ctx){
        trace("TRACE httpget close\n");
        AmiTLS13_Close(ctx);
    }
    if(buf) FreeMem(buf, 1024);
    if(req) FreeMem(req, 512);
    trace("TRACE httpget done\n");
    return rc;
}


