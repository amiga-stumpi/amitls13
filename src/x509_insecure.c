#include <libraries/dos.h>
#include <proto/dos.h>
#include <string.h>
#include "x509_insecure.h"

static void xdbg(const char *s)
{
#ifdef AMITLS13_DEBUG
    if(s) Write(Output(), (APTR)s, strlen(s));
#else
    (void)s;
#endif
}

static void xdbg_num(LONG n)
{
#ifdef AMITLS13_DEBUG
    char b[16];
    char t[14];
    WORD i=0;
    WORD p=0;
    if(n<0){ xdbg("-"); n=-n; }
    do{ t[i++]=(char)('0'+(n%10)); n/=10; }while(n && i<13);
    while(i>0) b[p++]=t[--i];
    b[p]=0;
    xdbg(b);
#else
    (void)n;
#endif
}

static void ix_start_chain(const br_x509_class **ctx, const char *server_name)
{
    AmiTLS13InsecureX509Context *xc;
    xc=(AmiTLS13InsecureX509Context *)(void *)ctx;
    xdbg("X509 start_chain "); xdbg(server_name ? server_name : "(null)"); xdbg("\n");
    xc->pkey=0;
    xc->cert_index=0;
    xc->failed=0;
    (void)server_name;
}

static void ix_start_cert(const br_x509_class **ctx, uint32_t length)
{
    AmiTLS13InsecureX509Context *xc;
    xc=(AmiTLS13InsecureX509Context *)(void *)ctx;
    xdbg("X509 start_cert idx="); xdbg_num(xc->cert_index); xdbg(" len="); xdbg_num((LONG)length); xdbg("\n");
    if(xc->cert_index==0){
        br_x509_decoder_init(&xc->decoder, 0, 0);
    }
    (void)length;
}

static void ix_append(const br_x509_class **ctx, const unsigned char *buf, size_t len)
{
    AmiTLS13InsecureX509Context *xc;
    xc=(AmiTLS13InsecureX509Context *)(void *)ctx;
    if(xc->cert_index==0){
        xdbg("X509 append len="); xdbg_num((LONG)len); xdbg("\n");
        br_x509_decoder_push(&xc->decoder, buf, len);
        xdbg("X509 append done err="); xdbg_num((LONG)br_x509_decoder_last_error(&xc->decoder)); xdbg("\n");
    }
}

static void ix_end_cert(const br_x509_class **ctx)
{
    AmiTLS13InsecureX509Context *xc;
    xc=(AmiTLS13InsecureX509Context *)(void *)ctx;
    xdbg("X509 end_cert idx="); xdbg_num(xc->cert_index); xdbg("\n");
    if(xc->cert_index==0){
        xdbg("X509 get_pkey\n");
        xc->pkey=br_x509_decoder_get_pkey(&xc->decoder);
        xdbg("X509 pkey ptr="); xdbg_num((LONG)xc->pkey); xdbg(" err="); xdbg_num((LONG)br_x509_decoder_last_error(&xc->decoder)); xdbg("\n");
        if(!xc->pkey) xc->failed=1;
    }
    xc->cert_index++;
}

static unsigned ix_end_chain(const br_x509_class **ctx)
{
    AmiTLS13InsecureX509Context *xc;
    xc=(AmiTLS13InsecureX509Context *)(void *)ctx;
    xdbg("X509 end_chain failed="); xdbg_num(xc->failed); xdbg(" pkey="); xdbg_num((LONG)xc->pkey); xdbg("\n");
    return (xc->failed || !xc->pkey) ? BR_ERR_X509_BAD_SERVER_NAME : 0;
}

static const br_x509_pkey *ix_get_pkey(const br_x509_class *const *ctx, unsigned *usages)
{
    const AmiTLS13InsecureX509Context *xc;
    xc=(const AmiTLS13InsecureX509Context *)(const void *)ctx;
    xdbg("X509 get_pkey cb pkey="); xdbg_num((LONG)xc->pkey); xdbg("\n");
    if(usages) *usages=BR_KEYTYPE_KEYX|BR_KEYTYPE_SIGN;
    return xc->pkey;
}

static const br_x509_class ix_vtable = {
    sizeof(AmiTLS13InsecureX509Context),
    ix_start_chain,
    ix_start_cert,
    ix_append,
    ix_end_cert,
    ix_end_chain,
    ix_get_pkey
};

void amitls13_x509_insecure_init(AmiTLS13InsecureX509Context *ctx)
{
    memset(ctx,0,sizeof(*ctx));
    ctx->vtable=&ix_vtable;
}
