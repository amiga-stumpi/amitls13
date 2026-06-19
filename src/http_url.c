#include <exec/types.h>
#include <string.h>
#include "amitls13.h"
#include "http_url.h"

static int starts_with(const char *s, const char *prefix)
{
    while(*prefix){
        if(*s++ != *prefix++) return 0;
    }
    return 1;
}

static UWORD parse_port(const char *s, const char **end)
{
    ULONG v;
    v = 0;
    while(*s >= '0' && *s <= '9'){
        v = (v * 10) + (ULONG)(*s - '0');
        if(v > 65535UL) v = 65535UL;
        s++;
    }
    *end = s;
    return (UWORD)v;
}

LONG amitls13_parse_url(const char *url, AmiTLS13Url *out)
{
    const char *p;
    const char *h;
    UWORD n;
    UWORD host_max;
    UWORD path_max;

    if(!url || !out) return AMITLS13_ERR_URL;
    memset(out, 0, sizeof(*out));
    host_max=(UWORD)sizeof(out->host);
    path_max=(UWORD)sizeof(out->path);

    if(starts_with(url, "https://")){
        out->https = 1;
        out->port = 443;
        p = url + 8;
    } else if(starts_with(url, "http://")){
        out->https = 0;
        out->port = 80;
        p = url + 7;
    } else {
        return AMITLS13_ERR_URL;
    }

    h = p;
    n = 0;
    while(*p && *p != '/' && *p != ':' && n + 1 < host_max){
        out->host[n++] = *p++;
    }
    out->host[n] = 0;
    if(n == 0) return AMITLS13_ERR_URL;

    if(*p == ':'){
        p++;
        out->port = parse_port(p, &p);
        if(out->port == 0) return AMITLS13_ERR_URL;
    }

    if(*p == '/'){
        n = 0;
        while(*p && n + 1 < path_max) out->path[n++] = *p++;
        out->path[n] = 0;
    } else {
        strcpy(out->path, "/");
    }

    (void)h;
    return AMITLS13_OK;
}
