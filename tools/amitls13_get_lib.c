#include <exec/types.h>
#include <exec/libraries.h>
#include <libraries/dos.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include <string.h>
#include "amitls13.h"
#include "amitls13_libbase.h"
#include "socket_os13.h"

LONG __stack = 131072;
struct Library *AmiTLS13Base = 0;

static BPTR g_tool_output = 0;

static void out(const char *s){ BPTR outfh; if(!s) return; outfh = g_tool_output ? g_tool_output : Output(); Write(outfh, (APTR)s, strlen(s)); }
static void out_num(LONG n){ char b[16]; char t[14]; WORD i; WORD p; if(n<0){ out("-"); n=-n; } i=0; do{ t[i++]=(char)('0'+(n%10)); n/=10; }while(n && i<13); p=0; while(i>0) b[p++]=t[--i]; b[p]=0; out(b); }

int main(int argc, char **argv)
{
    LONG rc;
    const char *url;
    const char *outfile;
    const char *logfile;
    WORD argi;

    if(argc < 2){
        out("Usage: amitls13_get_lib [LOG=FILE] URL [OUTFILE]\n");
        return 10;
    }

    logfile = 0;
    argi = 1;
    if(argc > 1 && strncmp(argv[argi], "LOG=", 4) == 0){
        logfile = argv[argi] + 4;
        argi++;
    }
    if(argi >= argc){
        out("Usage: amitls13_get_lib [LOG=FILE] URL [OUTFILE]\n");
        return 10;
    }

    AmiTLS13Base = OpenLibrary((STRPTR)AMITLS13NAME, AMITLS13VERSION);
    if(!AmiTLS13Base){ out("OpenLibrary amitls13.library failed\n"); return 20; }

    if(logfile && logfile[0]){
        g_tool_output = Open((STRPTR)logfile, MODE_NEWFILE);
        if(!g_tool_output){ out("Log open failed\n"); CloseLibrary(AmiTLS13Base); return 15; }
        AmiTLS13_SetDebugOutput(g_tool_output);
    }

    url = argv[argi];
    outfile = (argi + 1 < argc) ? argv[argi + 1] : "RAM:amitls13_get.out";

    rc = AmiTLS13_Init();
    if(rc != AMITLS13_OK){ out("Socket init failed: "); out_num(rc); out("\n"); CloseLibrary(AmiTLS13Base); return 25; }

    out("AmiTLS13 library GET: "); out(url); out("\n");
    rc = AmiTLS13_HTTPGet(url, outfile, AMITLS13F_INSECURE);

    if(rc < 0){
        out("GET failed: "); out_num(rc); out(" Socket Errno: "); out_num(AmiTLS13_SocketErrno()); out("\n");
        AmiTLS13_Exit();
        if(g_tool_output){ AmiTLS13_SetDebugOutput(0); Close(g_tool_output); g_tool_output=0; }
        CloseLibrary(AmiTLS13Base);
        Exit(40);
        return 40;
    }

    out("Received bytes: "); out_num(rc); out("\nSaved to: "); out(outfile); out("\n");
    AmiTLS13_Exit();
    if(g_tool_output){ AmiTLS13_SetDebugOutput(0); Close(g_tool_output); g_tool_output=0; }
    CloseLibrary(AmiTLS13Base);
    out("Program end ok\n");
    Exit(0);
    return 0;
}
