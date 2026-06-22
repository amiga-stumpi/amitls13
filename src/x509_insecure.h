#ifndef AMITLS13_X509_INSECURE_H
#define AMITLS13_X509_INSECURE_H

#include <exec/types.h>
#include <bearssl.h>

typedef struct AmiTLS13InsecureX509Context {
    const br_x509_class *vtable;
    br_x509_decoder_context decoder;
    br_x509_pkey pkey;
    UBYTE key_data[BR_X509_BUFSIZE_KEY];
    size_t key_data_len;
    UBYTE leaf_key_sha256[32];
    UBYTE pin_sha256[32];
    UBYTE pin_enabled;
    UWORD cert_index;
    UBYTE have_pkey;
    UBYTE failed;
} AmiTLS13InsecureX509Context;

void amitls13_x509_insecure_init(AmiTLS13InsecureX509Context *ctx);
void amitls13_x509_set_pubkey_pin_sha256(AmiTLS13InsecureX509Context *ctx, const UBYTE *sha256);

#endif
