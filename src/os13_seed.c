#include <exec/types.h>
#include <exec/tasks.h>
#include <exec/execbase.h>
#include <libraries/dos.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include <bearssl.h>

extern struct ExecBase *SysBase;

static int os13_seed_prng(const br_prng_class **ctx)
{
    struct DateStamp ds;
    struct Task *task;
    ULONG seed[10];
    ULONG i;

    task=(struct Task *)FindTask(0);
    DateStamp(&ds);

    seed[0]=(ULONG)ds.ds_Days;
    seed[1]=(ULONG)ds.ds_Minute;
    seed[2]=(ULONG)ds.ds_Tick;
    seed[3]=(ULONG)task;
    seed[4]=(ULONG)SysBase;
    seed[5]=(ULONG)SysBase->VBlankFrequency;
    seed[6]=(ULONG)SysBase->ex_EClockFrequency;
    seed[7]=(ULONG)SysBase->DispCount;
    seed[8]=(ULONG)AvailMem(MEMF_ANY);
    seed[9]=(ULONG)AvailMem(MEMF_CHIP);

    for(i=0;i<10;i++) seed[i]^=(seed[(i+3)%10]<<7)^(seed[(i+5)%10]>>3);
    (*ctx)->update(ctx, seed, sizeof(seed));
    return 1;
}

br_prng_seeder br_prng_seeder_system(const char **name)
{
    if(name) *name="amigaos13";
    return os13_seed_prng;
}
