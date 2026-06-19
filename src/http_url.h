#ifndef AMITLS13_HTTP_URL_H
#define AMITLS13_HTTP_URL_H

#include <exec/types.h>

typedef struct AmiTLS13Url {
    char host[128];
    char path[256];
    UWORD port;
    UBYTE https;
} AmiTLS13Url;

LONG amitls13_parse_url(const char *url, AmiTLS13Url *out);

#endif
