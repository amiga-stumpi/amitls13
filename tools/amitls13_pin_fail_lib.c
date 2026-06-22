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

int main(int argc, char **argv)
{
    const char *url;
    UBYTE bad_pin[32];
    LONG rc;
    WORD i;

    if(argc < 2){ out("Usage: amitls13_pin_fail_lib URL\n"); return 10; }
    url = argv[1];
    for(i=0;i<32;i++) bad_pin[i]=0;

    AmiTLS13Base = OpenLibrary((STRPTR)AMITLS13NAME, AMITLS13VERSION);
    if(!AmiTLS13Base){ out("OpenLibrary amitls13.library failed\n"); return 20; }

    rc = AmiTLS13_Init();
    if(rc != AMITLS13_OK){ out("Init failed: "); out_num(rc); out("\n"); CloseLibrary(AmiTLS13Base); return 25; }

    rc = AmiTLS13_SetPublicKeyPinSHA256(bad_pin, 32);
    if(rc != AMITLS13_OK){ out("Set pin failed: "); out_num(rc); out("\n"); AmiTLS13_Exit(); CloseLibrary(AmiTLS13Base); return 30; }

    out("AmiTLS13 pin mismatch test: "); out(url); out("\n");
    rc = AmiTLS13_HTTPGet(url, "RAM:amitls13_pin_fail.out", AMITLS13F_INSECURE | AMITLS13F_PIN_PUBKEY_SHA256);

    AmiTLS13_SetPublicKeyPinSHA256(0, 0);
    AmiTLS13_Exit();
    CloseLibrary(AmiTLS13Base);

    if(rc < 0){
        out("Pin mismatch rejected as expected: "); out_num(rc); out("\n");
        return 0;
    }

    out("Unexpected success, pin check failed open\n");
    return 50;
}
