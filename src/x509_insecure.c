#include <libraries/dos.h>
#include <proto/dos.h>
#include <string.h>
#include "x509_insecure.h"
#include "amitls13.h"

static void xdbg(const char *s)
{
#ifdef AMITLS13_DEBUG
    if(s) AmiTLS13_DebugWrite(s);
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


static void ix_clear_pkey(AmiTLS13InsecureX509Context *xc)
{
    xc->have_pkey=0;
    xc->key_data_len=0;
    memset(&xc->pkey,0,sizeof(xc->pkey));
    memset(xc->key_data,0,sizeof(xc->key_data));
    memset(xc->leaf_key_sha256,0,sizeof(xc->leaf_key_sha256));
}

static UBYTE ix_eq32(const UBYTE *a, const UBYTE *b)
{
    UBYTE v = 0;
    UWORD i;
    for(i=0;i<32;i++) v |= (UBYTE)(a[i] ^ b[i]);
    return v == 0;
}

static void ix_hash_leaf_key(AmiTLS13InsecureX509Context *xc)
{
    br_sha256_context sh;
    memset(xc->leaf_key_sha256,0,sizeof(xc->leaf_key_sha256));
    br_sha256_init(&sh);
    br_sha256_update(&sh, xc->key_data, xc->key_data_len);
    br_sha256_out(&sh, xc->leaf_key_sha256);
}

static UBYTE ix_copy_pkey(AmiTLS13InsecureX509Context *xc, const br_x509_pkey *pk)
{
    size_t nlen;
    size_t elen;
    size_t qlen;

    ix_clear_pkey(xc);
    if(!pk) return 0;
    xc->pkey.key_type=pk->key_type;
    if(pk->key_type==BR_KEYTYPE_RSA){
        nlen=pk->key.rsa.nlen;
        elen=pk->key.rsa.elen;
        if(nlen+elen>sizeof(xc->key_data)) return 0;
        memcpy(xc->key_data, pk->key.rsa.n, nlen);
        memcpy(xc->key_data+nlen, pk->key.rsa.e, elen);
        xc->pkey.key.rsa.n=xc->key_data;
        xc->pkey.key.rsa.nlen=nlen;
        xc->pkey.key.rsa.e=xc->key_data+nlen;
        xc->pkey.key.rsa.elen=elen;
        xc->key_data_len=nlen+elen;
        xc->have_pkey=1;
        return 1;
    }
    if(pk->key_type==BR_KEYTYPE_EC){
        qlen=pk->key.ec.qlen;
        if(qlen>sizeof(xc->key_data)) return 0;
        memcpy(xc->key_data, pk->key.ec.q, qlen);
        xc->pkey.key.ec.curve=pk->key.ec.curve;
        xc->pkey.key.ec.q=xc->key_data;
        xc->pkey.key.ec.qlen=qlen;
        xc->key_data_len=qlen;
        xc->have_pkey=1;
        return 1;
    }
    return 0;
}

static void ix_start_chain(const br_x509_class **ctx, const char *server_name)
{
    AmiTLS13InsecureX509Context *xc;
    xc=(AmiTLS13InsecureX509Context *)(void *)ctx;
    xdbg("X509 start_chain\n");
    ix_clear_pkey(xc);
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
        br_x509_decoder_push(&xc->decoder, buf, len);
    }
}

static void ix_end_cert(const br_x509_class **ctx)
{
    AmiTLS13InsecureX509Context *xc;
    xc=(AmiTLS13InsecureX509Context *)(void *)ctx;
    xdbg("X509 end_cert idx="); xdbg_num(xc->cert_index); xdbg("\n");
    if(xc->cert_index==0){
        const br_x509_pkey *pk;
        pk=br_x509_decoder_get_pkey(&xc->decoder);
        if(!ix_copy_pkey(xc, pk)){
            xc->failed=1;
        } else {
            ix_hash_leaf_key(xc);
            if(xc->pin_enabled && !ix_eq32(xc->leaf_key_sha256, xc->pin_sha256)){
                xdbg("X509 public key pin mismatch\n");
                xc->failed=1;
            }
        }
        xdbg("X509 pkey copied="); xdbg_num((LONG)xc->have_pkey); xdbg(" type="); xdbg_num((LONG)xc->pkey.key_type); xdbg("\n");
    }
    xc->cert_index++;
}

static unsigned ix_end_chain(const br_x509_class **ctx)
{
    AmiTLS13InsecureX509Context *xc;
    xc=(AmiTLS13InsecureX509Context *)(void *)ctx;
    xdbg("X509 end_chain failed="); xdbg_num(xc->failed); xdbg(" have_pkey="); xdbg_num((LONG)xc->have_pkey); xdbg("\n");
    return (xc->failed || !xc->have_pkey) ? BR_ERR_X509_BAD_SERVER_NAME : 0;
}

static const br_x509_pkey *ix_get_pkey(const br_x509_class *const *ctx, unsigned *usages)
{
    const AmiTLS13InsecureX509Context *xc;
    xc=(const AmiTLS13InsecureX509Context *)(const void *)ctx;
    xdbg("X509 get_pkey cb have_pkey="); xdbg_num((LONG)xc->have_pkey); xdbg("\n");
    if(usages) *usages=BR_KEYTYPE_KEYX|BR_KEYTYPE_SIGN;
    return xc->have_pkey ? &xc->pkey : 0;
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

void amitls13_x509_set_pubkey_pin_sha256(AmiTLS13InsecureX509Context *ctx, const UBYTE *sha256)
{
    if(!ctx) return;
    if(!sha256){
        ctx->pin_enabled=0;
        memset(ctx->pin_sha256,0,sizeof(ctx->pin_sha256));
        return;
    }
    memcpy(ctx->pin_sha256, sha256, 32);
    ctx->pin_enabled=1;
}
