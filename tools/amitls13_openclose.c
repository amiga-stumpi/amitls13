#include <exec/types.h>
#include <exec/libraries.h>
#include <libraries/dos.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include "amitls13_libbase.h"

LONG __stack = 8192;

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
    if(!s || !s[0]) return 10;
    while(*s >= '0' && *s <= '9'){
        n = (n * 10) + (*s - '0');
        s++;
    }
    if(n <= 0) n = 1;
    if(n > 1000) n = 1000;
    return n;
}

int main(int argc, char **argv)
{
    LONG count;
    LONG i;
    struct Library *base;

    count = (argc > 1) ? parse_count(argv[1]) : 10;
    out("AmiTLS13 open/close test: "); out_num(count); out(" cycles\n");

    for(i = 0; i < count; i++){
        base = OpenLibrary((STRPTR)AMITLS13NAME, AMITLS13VERSION);
        if(!base){
            out("OpenLibrary failed at cycle "); out_num(i + 1); out("\n");
            Exit(20);
            return 20;
        }
        CloseLibrary(base);
    }

    out("Open/close test ok\n");
    Exit(0);
    return 0;
}
