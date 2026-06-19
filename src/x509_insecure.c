#include <string.h>
#include "x509_insecure.h"

static void ix_start_chain(const br_x509_class **ctx, const char *server_name)
{
    AmiTLS13InsecureX509Context *xc;
    xc=(AmiTLS13InsecureX509Context *)(void *)ctx;
    xc->pkey=0;
    xc->cert_index=0;
    xc->failed=0;
    (void)server_name;
}

static void ix_start_cert(const br_x509_class **ctx, uint32_t length)
{
    AmiTLS13InsecureX509Context *xc;
    xc=(AmiTLS13InsecureX509Context *)(void *)ctx;
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
        br_x509_decoder_push(&xc->decoder, buf, len);
    }
}

static void ix_end_cert(const br_x509_class **ctx)
{
    AmiTLS13InsecureX509Context *xc;
    xc=(AmiTLS13InsecureX509Context *)(void *)ctx;
    if(xc->cert_index==0){
        xc->pkey=br_x509_decoder_get_pkey(&xc->decoder);
        if(!xc->pkey) xc->failed=1;
    }
    xc->cert_index++;
}

static unsigned ix_end_chain(const br_x509_class **ctx)
{
    AmiTLS13InsecureX509Context *xc;
    xc=(AmiTLS13InsecureX509Context *)(void *)ctx;
    return (xc->failed || !xc->pkey) ? BR_ERR_X509_BAD_SERVER_NAME : 0;
}

static const br_x509_pkey *ix_get_pkey(const br_x509_class *const *ctx, unsigned *usages)
{
    const AmiTLS13InsecureX509Context *xc;
    xc=(const AmiTLS13InsecureX509Context *)(const void *)ctx;
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
