#include <exec/types.h>
#include <exec/libraries.h>
#include <libraries/dos.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include <string.h>
#include "amitls13.h"
#include "amitls13_libbase.h"

LONG __stack = 131072;
struct Library *AmiTLS13Base = 0;

static BPTR g_tool_output = 0;
static UBYTE g_buf[2048];
static char g_host[128];
static char g_path[256];
static char g_req[512];

static void out(const char *s){ BPTR outfh; if(!s) return; outfh = g_tool_output ? g_tool_output : Output(); Write(outfh, (APTR)s, strlen(s)); }
static void out_num(LONG n){ char b[16]; char t[14]; WORD i; WORD p; if(n<0){ out("-"); n=-n; } i=0; do{ t[i++]=(char)("0"[0]+(n%10)); n/=10; }while(n && i<13); p=0; while(i>0) b[p++]=t[--i]; b[p]=0; out(b); }

static int starts_with(const char *s, const char *p){ while(*p){ if(*s++ != *p++) return 0; } return 1; }

static UWORD parse_port(const char *s, const char **end)
{
    ULONG v = 0;
    while(*s >= '0' && *s <= '9') { v = (v * 10) + (ULONG)(*s - '0'); ++s; }
    *end = s;
    return (UWORD)v;
}

static int parse_url(const char *url, char *host, LONG host_size, char *path, LONG path_size, UWORD *port)
{
    const char *p;
    const char *slash;
    const char *colon;
    LONG len;
    if(starts_with(url, "https://")) { p = url + 8; *port = 443; }
    else return 0;
    slash = p;
    while(*slash && *slash != '/') ++slash;
    colon = p;
    while(colon < slash && *colon != ':') ++colon;
    len = (LONG)((colon < slash && *colon == ':') ? (colon - p) : (slash - p));
    if(len <= 0 || len >= host_size) return 0;
    memcpy(host, p, len);
    host[len] = 0;
    if(colon < slash && *colon == ':') {
        ++colon;
        *port = parse_port(colon, &colon);
        if(*port == 0) return 0;
    }
    if(*slash) {
        len = strlen(slash);
        if(len >= path_size) return 0;
        strcpy(path, slash);
    } else {
        strcpy(path, "/");
    }
    return 1;
}

int main(int argc, char **argv)
{
    const char *url;
    const char *outfile;
    const char *logfile;
    struct AmiTLS13Context *ctx = 0;
    BPTR f = 0;
    LONG rc;
    LONG n;
    UWORD port;
    WORD argi;

    if(argc < 2){ out("Usage: amitls13_stream_test_lib [LOG=FILE] https://host/path [OUTFILE]\n"); return 10; }
    logfile = 0;
    argi = 1;
    if(strncmp(argv[argi], "LOG=", 4) == 0){ logfile = argv[argi] + 4; ++argi; }
    if(argi >= argc){ out("Usage: amitls13_stream_test_lib [LOG=FILE] https://host/path [OUTFILE]\n"); return 10; }
    url = argv[argi];
    outfile = (argi + 1 < argc) ? argv[argi + 1] : "RAM:amitls13_stream.out";
    if(!parse_url(url, g_host, sizeof(g_host), g_path, sizeof(g_path), &port)){ out("URL parse failed\n"); return 12; }

    AmiTLS13Base = OpenLibrary((STRPTR)AMITLS13NAME, AMITLS13VERSION);
    if(!AmiTLS13Base){ out("OpenLibrary amitls13.library failed\n"); return 20; }
    if(logfile && logfile[0]){
        g_tool_output = Open((STRPTR)logfile, MODE_NEWFILE);
        if(!g_tool_output){ out("Log open failed\n"); CloseLibrary(AmiTLS13Base); return 15; }
        AmiTLS13_SetDebugOutput(g_tool_output);
    }
    rc = AmiTLS13_Init();
    if(rc != AMITLS13_OK){ out("Init failed "); out_num(rc); out("\n"); goto fail; }

    out("LL connect host="); out(g_host); out(" port="); out_num(port); out("\n");
    ctx = AmiTLS13_Connect(g_host, port, AMITLS13F_INSECURE);
    if(!ctx){ out("Connect failed socket errno="); out_num(AmiTLS13_SocketErrno()); out("\n"); goto fail; }
    out("LL start tls\n");
    rc = AmiTLS13_StartTLS(ctx, g_host);
    if(rc != AMITLS13_OK){ out("StartTLS failed "); out_num(rc); out("\n"); goto fail; }
    out("LL write request\n");
    strcpy(g_req, "GET ");
    strncat(g_req, g_path, sizeof(g_req)-strlen(g_req)-1);
    strncat(g_req, " HTTP/1.1\r\nHost: ", sizeof(g_req)-strlen(g_req)-1);
    strncat(g_req, g_host, sizeof(g_req)-strlen(g_req)-1);
    strncat(g_req, "\r\nUser-Agent: AmiTLS13StreamTest/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n", sizeof(g_req)-strlen(g_req)-1);
    rc = AmiTLS13_Write(ctx, (const UBYTE *)g_req, strlen(g_req));
    if(rc < 0){ out("Write failed "); out_num(rc); out(" last="); out_num(AmiTLS13_GetLastError(ctx)); out("\n"); goto fail; }
    out("LL read begin\n");
    n = AmiTLS13_Read(ctx, g_buf, sizeof(g_buf));
    out("LL read ret="); out_num(n); out(" last="); out_num(AmiTLS13_GetLastError(ctx)); out("\n");
    if(n <= 0) goto fail;
    f = Open((STRPTR)outfile, MODE_NEWFILE);
    if(f){ Write(f, g_buf, n); Close(f); f = 0; }
    out("Saved first bytes to "); out(outfile); out("\n");
    if(ctx) AmiTLS13_Close(ctx);
    AmiTLS13_Exit();
    if(g_tool_output){ AmiTLS13_SetDebugOutput(0); Close(g_tool_output); g_tool_output=0; }
    CloseLibrary(AmiTLS13Base);
    out("Program end ok\n");
    Exit(0);
    return 0;

fail:
    if(ctx) AmiTLS13_Close(ctx);
    AmiTLS13_Exit();
    if(g_tool_output){ AmiTLS13_SetDebugOutput(0); Close(g_tool_output); g_tool_output=0; }
    if(AmiTLS13Base) CloseLibrary(AmiTLS13Base);
    out("Program end failure\n");
    Exit(40);
    return 40;
}
