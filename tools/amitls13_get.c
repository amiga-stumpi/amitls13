#include <exec/types.h>
#include <libraries/dos.h>
#include <proto/dos.h>
#include <string.h>
#include "amitls13.h"
#include "http_url.h"
#include "socket_os13.h"

LONG __stack = 131072;

static void out(const char *s){ Write(Output(), (APTR)s, strlen(s)); }
static void out_num(LONG n){ char b[16]; char t[14]; WORD i; WORD p; if(n<0){ out("-"); n=-n; } i=0; do{ t[i++]=(char)('0'+(n%10)); n/=10; }while(n && i<13); p=0; while(i>0) b[p++]=t[--i]; b[p]=0; out(b); }

int main(int argc, char **argv)
{
    LONG rc;
    const char *url;
    const char *outfile;

    if(argc < 2){
        out("Usage: amitls13_get URL [OUTFILE]\n");
        out("Phase 1 note: HTTPS uses BearSSL with temporary insecure certificate handling.\n");
        return 10;
    }

    url = argv[1];
    outfile = (argc >= 3) ? argv[2] : "RAM:amitls13_get.out";

    rc = AmiTLS13_Init();
    if(rc != AMITLS13_OK){ out("Socket init failed: "); out_num(rc); out("\n"); return 20; }

    out("AmiTLS13 GET: "); out(url); out("\n");
    rc = AmiTLS13_HTTPGet(url, outfile, AMITLS13F_INSECURE);
    AmiTLS13_Exit();

    if(rc == AMITLS13_ERR_TLS_DISABLED){
        out("TLS setup failed. Check TLS debug line above.\n");
        return 30;
    }
    if(rc < 0){ out("GET failed: "); out_num(rc); out(" Socket Errno: "); out_num(amitls13_socket_errno()); out("\n"); return 40; }

    out("Received bytes: "); out_num(rc); out("\nSaved to: "); out(outfile); out("\n");
    return 0;
}
