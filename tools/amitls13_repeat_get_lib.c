#include <exec/types.h>
#include <exec/libraries.h>
#include <libraries/dos.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include "amitls13.h"
#include "amitls13_libbase.h"

LONG __stack = 131072;
struct Library *AmiTLS13Base = 0;

static ULONG slen(const char *s)
{
    ULONG n = 0;
    if(!s) return 0;
    while(s[n]) n++;
    return n;
}

static void out(const char *s)
{
    if(s) Write(Output(), (APTR)s, slen(s));
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

static LONG parse_count(const char *s)
{
    LONG n = 0;
    if(!s || !s[0]) return 3;
    while(*s >= '0' && *s <= '9'){
        n = (n * 10) + (*s - '0');
        s++;
    }
    if(n <= 0) n = 1;
    if(n > 50) n = 50;
    return n;
}

static void make_outfile(char *buf, LONG index)
{
    char t[8];
    WORD i = 0;
    WORD p;
    LONG n = index;
    const char *prefix = "RAM:amitls13_repeat_";

    p = 0;
    while(prefix[p]){ buf[p] = prefix[p]; p++; }
    do { t[i++] = (char)('0' + (n % 10)); n /= 10; } while(n && i < 7);
    while(i > 0) buf[p++] = t[--i];
    buf[p++] = '.';
    buf[p++] = 'o';
    buf[p++] = 'u';
    buf[p++] = 't';
    buf[p] = 0;
}

int main(int argc, char **argv)
{
    const char *url;
    LONG count;
    LONG i;
    LONG rc;
    char outfile[40];

    if(argc < 2){
        out("Usage: amitls13_repeat_get_lib URL [COUNT]\n");
        return 10;
    }

    url = argv[1];
    count = (argc > 2) ? parse_count(argv[2]) : 3;

    AmiTLS13Base = OpenLibrary((STRPTR)AMITLS13NAME, AMITLS13VERSION);
    if(!AmiTLS13Base){ out("OpenLibrary amitls13.library failed\n"); return 20; }

    out("AmiTLS13 repeat GET: "); out(url); out(" cycles="); out_num(count); out("\n");

    for(i = 0; i < count; i++){
        rc = AmiTLS13_Init();
        if(rc != AMITLS13_OK){
            out("Init failed at cycle "); out_num(i + 1); out(": "); out_num(rc); out("\n");
            CloseLibrary(AmiTLS13Base);
            Exit(25);
            return 25;
        }

        make_outfile(outfile, i + 1);
        out("Cycle "); out_num(i + 1); out("... ");
        rc = AmiTLS13_HTTPGet(url, outfile, AMITLS13F_INSECURE);
        AmiTLS13_Exit();

        if(rc < 0){
            out("failed rc="); out_num(rc); out(" socket="); out_num(AmiTLS13_SocketErrno()); out("\n");
            CloseLibrary(AmiTLS13Base);
            Exit(40);
            return 40;
        }
        out("ok bytes="); out_num(rc); out("\n");
    }

    CloseLibrary(AmiTLS13Base);
    out("Repeat GET test ok\n");
    Exit(0);
    return 0;
}
