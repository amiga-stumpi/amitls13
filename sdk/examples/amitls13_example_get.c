#include <exec/types.h>
#include <exec/libraries.h>
#include <libraries/dos.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include "amitls13.h"
#include "amitls13_libbase.h"

LONG __stack = 131072;
struct Library *AmiTLS13Base = 0;

static ULONG s_len(const char *s)
{
    ULONG n = 0;
    if(!s) return 0;
    while(s[n]) n++;
    return n;
}

static void out(const char *s)
{
    if(s) Write(Output(), (APTR)s, s_len(s));
}

static void out_num(LONG n)
{
    char b[16];
    char t[14];
    WORD i = 0;
    WORD p = 0;

    if(n < 0){ out("-"); n = -n; }
    do { t[i++] = (char)('0' + (n % 10)); n /= 10; } while(n && i < 13);
    while(i > 0) b[p++] = t[--i];
    b[p] = 0;
    out(b);
}

int main(int argc, char **argv)
{
    const char *url;
    const char *outfile;
    LONG rc;

    if(argc < 2){
        out("Usage: amitls13_example_get URL [OUTFILE]\n");
        return 10;
    }

    url = argv[1];
    outfile = (argc > 2) ? argv[2] : "RAM:amitls13_example.out";

    AmiTLS13Base = OpenLibrary((STRPTR)AMITLS13NAME, AMITLS13VERSION);
    if(!AmiTLS13Base){
        out("OpenLibrary amitls13.library failed\n");
        return 20;
    }

    rc = AmiTLS13_Init();
    if(rc != AMITLS13_OK){
        out("AmiTLS13_Init failed: "); out_num(rc); out("\n");
        CloseLibrary(AmiTLS13Base);
        return 25;
    }

    rc = AmiTLS13_HTTPGet(url, outfile, AMITLS13F_INSECURE);
    if(rc < 0){
        out("GET failed: "); out_num(rc); out(" socket errno="); out_num(AmiTLS13_SocketErrno()); out("\n");
        AmiTLS13_Exit();
        CloseLibrary(AmiTLS13Base);
        return 40;
    }

    out("Received bytes: "); out_num(rc); out("\nSaved to: "); out(outfile); out("\n");

    AmiTLS13_Exit();
    CloseLibrary(AmiTLS13Base);
    return 0;
}
