#include <exec/types.h>
#include <exec/libraries.h>
#include <exec/resident.h>
#include <exec/execbase.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include "amitls13.h"

#define AMITLS13_LIB_VERSION 0
#define AMITLS13_LIB_REVISION 1

struct AmiTLS13Library {
    struct Library lib;
    BPTR seg_list;
    struct ExecBase *sys_base;
    UWORD open_count;
    UBYTE delete_pending;
    UBYTE pad;
};

struct ExecBase *SysBase = 0;

static const char lib_name[] = "amitls13.library";
static const char lib_id[] = "amitls13.library 0.1 (20.06.2026)\r\n";

struct AmiTLS13Library *AmiTLS13Lib_Init(struct AmiTLS13Library *base, BPTR seg_list, struct ExecBase *sys_base);
struct AmiTLS13Library *AmiTLS13Lib_Open(struct AmiTLS13Library *base);
BPTR AmiTLS13Lib_Close(struct AmiTLS13Library *base);
BPTR AmiTLS13Lib_Expunge(struct AmiTLS13Library *base);
ULONG AmiTLS13Lib_ExtFunc(void);

APTR AmiTLS13Lib_VInit(void);
APTR AmiTLS13Lib_VOpen(void);
APTR AmiTLS13Lib_VClose(void);
APTR AmiTLS13Lib_VExpunge(void);
APTR AmiTLS13Lib_VExtFunc(void);
APTR AmiTLS13Lib_VInitAPI(void);
APTR AmiTLS13Lib_VExitAPI(void);
APTR AmiTLS13Lib_VSetDebugOutput(void);
APTR AmiTLS13Lib_VConnect(void);
APTR AmiTLS13Lib_VWrite(void);
APTR AmiTLS13Lib_VRead(void);
APTR AmiTLS13Lib_VCloseContext(void);
APTR AmiTLS13Lib_VGetLastError(void);
APTR AmiTLS13Lib_VSocketErrno(void);
APTR AmiTLS13Lib_VHTTPGet(void);

static APTR func_table[] = {
    (APTR)AmiTLS13Lib_VOpen,
    (APTR)AmiTLS13Lib_VClose,
    (APTR)AmiTLS13Lib_VExpunge,
    (APTR)AmiTLS13Lib_VExtFunc,
    (APTR)AmiTLS13Lib_VInitAPI,
    (APTR)AmiTLS13Lib_VExitAPI,
    (APTR)AmiTLS13Lib_VSetDebugOutput,
    (APTR)AmiTLS13Lib_VConnect,
    (APTR)AmiTLS13Lib_VWrite,
    (APTR)AmiTLS13Lib_VRead,
    (APTR)AmiTLS13Lib_VCloseContext,
    (APTR)AmiTLS13Lib_VGetLastError,
    (APTR)AmiTLS13Lib_VSocketErrno,
    (APTR)AmiTLS13Lib_VHTTPGet,
    (APTR)-1
};

struct AmiTLS13AutoInit {
    ULONG data_size;
    APTR *functions;
    APTR data;
    APTR init;
};

static const struct AmiTLS13AutoInit auto_init = {
    sizeof(struct AmiTLS13Library),
    func_table,
    0,
    (APTR)AmiTLS13Lib_VInit
};

const struct Resident amitls13_resident = {
    RTC_MATCHWORD,
    (struct Resident *)&amitls13_resident,
    (APTR)(&amitls13_resident + 1),
    RTF_AUTOINIT,
    AMITLS13_LIB_VERSION,
    NT_LIBRARY,
    0,
    (char *)lib_name,
    (char *)lib_id,
    (APTR)&auto_init
};

struct AmiTLS13Library *AmiTLS13Lib_Init(struct AmiTLS13Library *base, BPTR seg_list, struct ExecBase *sys_base)
{
    SysBase = sys_base;
    DOSBase = (struct DosLibrary *)OpenLibrary((STRPTR)"dos.library", 0);
    if(!DOSBase) return 0;

    base->lib.lib_Node.ln_Type = NT_LIBRARY;
    base->lib.lib_Node.ln_Pri = 0;
    base->lib.lib_Node.ln_Name = (char *)lib_name;
    base->lib.lib_Version = AMITLS13_LIB_VERSION;
    base->lib.lib_Revision = AMITLS13_LIB_REVISION;
    base->lib.lib_IdString = (APTR)lib_id;
    base->seg_list = seg_list;
    base->sys_base = sys_base;
    base->open_count = 0;
    base->delete_pending = 0;
    return base;
}

struct AmiTLS13Library *AmiTLS13Lib_Open(struct AmiTLS13Library *base)
{
    base->open_count++;
    base->lib.lib_OpenCnt++;
    base->lib.lib_Flags &= ~LIBF_DELEXP;
    return base;
}

BPTR AmiTLS13Lib_Close(struct AmiTLS13Library *base)
{
    if(base->open_count) base->open_count--;
    if(base->lib.lib_OpenCnt) base->lib.lib_OpenCnt--;
    if(base->lib.lib_OpenCnt == 0 && (base->lib.lib_Flags & LIBF_DELEXP)){
        return AmiTLS13Lib_Expunge(base);
    }
    return 0;
}

BPTR AmiTLS13Lib_Expunge(struct AmiTLS13Library *base)
{
    BPTR seg;

    if(base->lib.lib_OpenCnt != 0){
        base->lib.lib_Flags |= LIBF_DELEXP;
        return 0;
    }

    seg = base->seg_list;
    if(DOSBase){
        CloseLibrary((struct Library *)DOSBase);
        DOSBase = 0;
    }
    Remove((struct Node *)base);
    FreeMem((UBYTE *)base - base->lib.lib_NegSize, base->lib.lib_NegSize + base->lib.lib_PosSize);
    return seg;
}

ULONG AmiTLS13Lib_ExtFunc(void)
{
    return 0;
}
