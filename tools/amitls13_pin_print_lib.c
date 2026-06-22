#include <exec/types.h>
#include <exec/libraries.h>
#include <libraries/dos.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include "amitls13.h"
#include "amitls13_libbase.h"

LONG __stack = 131072;
struct Library *AmiTLS13Base = 0;

static ULONG slen(const char *s){ ULONG n=0; if(!s) return 0; while(s[n]) n++; return n; }
static void out(const char *s){ if(s) Write(Output(), (APTR)s, slen(s)); }
static void out_num(LONG n){ char b[16]; char t[14]; WORD i=0,p=0; if(n<0){ out("-"); n=-n; } do{ t[i++]=(char)('0'+(n%10)); n/=10; }while(n && i<13); while(i>0) b[p++]=t[--i]; b[p]=0; out(b); }
static void out_hex(UBYTE v){ static const char hx[]="0123456789abcdef"; char b[3]; b[0]=hx[(v>>4)&15]; b[1]=hx[v&15]; b[2]=0; out(b); }

int main(int argc, char **argv)
{
    const char *url;
    UBYTE pin[32];
    LONG rc;
    LONG total;
    WORD i;

    if(argc < 2){ out("Usage: amitls13_pin_print_lib URL\n"); return 10; }
    url = argv[1];

    AmiTLS13Base = OpenLibrary((STRPTR)AMITLS13NAME, AMITLS13VERSION);
    if(!AmiTLS13Base){ out("OpenLibrary amitls13.library failed\n"); return 20; }

    rc = AmiTLS13_Init();
    if(rc != AMITLS13_OK){ out("Init failed: "); out_num(rc); out("\n"); CloseLibrary(AmiTLS13Base); return 25; }

    AmiTLS13_SetPublicKeyPinSHA256(0, 0);
    out("AmiTLS13 pin print: "); out(url); out("\n");
    rc = AmiTLS13_HTTPGet(url, "RAM:amitls13_pin_print.out", AMITLS13F_INSECURE);
    total = rc;
    if(rc < 0){
        out("GET failed: "); out_num(rc); out(" Socket Errno: "); out_num(AmiTLS13_SocketErrno()); out("\n");
        AmiTLS13_Exit(); CloseLibrary(AmiTLS13Base); return 30;
    }

    rc = AmiTLS13_GetLastPeerPublicKeySHA256(pin, 32);
    if(rc != AMITLS13_OK){
        out("No peer public key hash available: "); out_num(rc); out("\n");
        AmiTLS13_Exit(); CloseLibrary(AmiTLS13Base); return 35;
    }

    out("Peer public key material SHA256: ");
    for(i=0;i<32;i++) out_hex(pin[i]);
    out("\n");
    out("Received bytes: "); out_num(total); out("\n");

    AmiTLS13_Exit();
    CloseLibrary(AmiTLS13Base);
    out("Program end ok\n");
    return 0;
}
