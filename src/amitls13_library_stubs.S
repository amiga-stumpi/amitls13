    .text

    .globl _AmiTLS13Lib_VInit
_AmiTLS13Lib_VInit:
    movem.l d2-d7/a2-a6,-(sp)
    move.l a6,-(sp)         /* SysBase */
    move.l a0,-(sp)         /* library base */
    move.l d0,-(sp)         /* seglist */
    jsr _AmiTLS13Lib_Init
    lea 12(sp),sp
    movem.l (sp)+,d2-d7/a2-a6
    rts

    .globl _AmiTLS13Lib_VOpen
_AmiTLS13Lib_VOpen:
    movem.l d2-d7/a2-a6,-(sp)
    move.l a6,-(sp)
    jsr _AmiTLS13Lib_Open
    addq.l #4,sp
    movem.l (sp)+,d2-d7/a2-a6
    rts

    .globl _AmiTLS13Lib_VClose
_AmiTLS13Lib_VClose:
    movem.l d2-d7/a2-a6,-(sp)
    move.l a6,-(sp)
    jsr _AmiTLS13Lib_Close
    addq.l #4,sp
    movem.l (sp)+,d2-d7/a2-a6
    rts

    .globl _AmiTLS13Lib_VExpunge
_AmiTLS13Lib_VExpunge:
    movem.l d2-d7/a2-a6,-(sp)
    move.l a6,-(sp)
    jsr _AmiTLS13Lib_Expunge
    addq.l #4,sp
    movem.l (sp)+,d2-d7/a2-a6
    rts

    .globl _AmiTLS13Lib_VExtFunc
_AmiTLS13Lib_VExtFunc:
    movem.l d2-d7/a2-a6,-(sp)
    jsr _AmiTLS13Lib_ExtFunc
    movem.l (sp)+,d2-d7/a2-a6
    rts

    .globl _AmiTLS13Lib_VInitAPI
_AmiTLS13Lib_VInitAPI:
    movem.l d2-d7/a2-a6,-(sp)
    jsr _AmiTLS13_Init
    movem.l (sp)+,d2-d7/a2-a6
    rts

    .globl _AmiTLS13Lib_VExitAPI
_AmiTLS13Lib_VExitAPI:
    movem.l d2-d7/a2-a6,-(sp)
    jsr _AmiTLS13_Exit
    movem.l (sp)+,d2-d7/a2-a6
    rts

    .globl _AmiTLS13Lib_VSetDebugOutput
_AmiTLS13Lib_VSetDebugOutput:
    movem.l d2-d7/a2-a6,-(sp)
    move.l d0,-(sp)
    jsr _AmiTLS13_SetDebugOutput
    addq.l #4,sp
    movem.l (sp)+,d2-d7/a2-a6
    rts

    .globl _AmiTLS13Lib_VConnect
_AmiTLS13Lib_VConnect:
    movem.l d2-d7/a2-a6,-(sp)
    move.l d1,-(sp)
    move.w d0,-(sp)
    clr.w -(sp)
    move.l a0,-(sp)
    jsr _AmiTLS13_Connect
    lea 12(sp),sp
    movem.l (sp)+,d2-d7/a2-a6
    rts

    .globl _AmiTLS13Lib_VWrite
_AmiTLS13Lib_VWrite:
    movem.l d2-d7/a2-a6,-(sp)
    move.l d0,-(sp)
    move.l a1,-(sp)
    move.l a0,-(sp)
    jsr _AmiTLS13_Write
    lea 12(sp),sp
    movem.l (sp)+,d2-d7/a2-a6
    rts

    .globl _AmiTLS13Lib_VRead
_AmiTLS13Lib_VRead:
    movem.l d2-d7/a2-a6,-(sp)
    move.l d0,-(sp)
    move.l a1,-(sp)
    move.l a0,-(sp)
    jsr _AmiTLS13_Read
    lea 12(sp),sp
    movem.l (sp)+,d2-d7/a2-a6
    rts

    .globl _AmiTLS13Lib_VCloseContext
_AmiTLS13Lib_VCloseContext:
    movem.l d2-d7/a2-a6,-(sp)
    move.l a0,-(sp)
    jsr _AmiTLS13_Close
    addq.l #4,sp
    movem.l (sp)+,d2-d7/a2-a6
    rts

    .globl _AmiTLS13Lib_VGetLastError
_AmiTLS13Lib_VGetLastError:
    movem.l d2-d7/a2-a6,-(sp)
    move.l a0,-(sp)
    jsr _AmiTLS13_GetLastError
    addq.l #4,sp
    movem.l (sp)+,d2-d7/a2-a6
    rts

    .globl _AmiTLS13Lib_VSocketErrno
_AmiTLS13Lib_VSocketErrno:
    movem.l d2-d7/a2-a6,-(sp)
    jsr _AmiTLS13_SocketErrno
    movem.l (sp)+,d2-d7/a2-a6
    rts

    .globl _AmiTLS13Lib_VHTTPGet
_AmiTLS13Lib_VHTTPGet:
    movem.l d2-d7/a2-a6,-(sp)
    move.l d0,-(sp)
    move.l a1,-(sp)
    move.l a0,-(sp)
    jsr _AmiTLS13_HTTPGet
    lea 12(sp),sp
    movem.l (sp)+,d2-d7/a2-a6
    rts

    .globl _AmiTLS13Lib_VSetPublicKeyPinSHA256
_AmiTLS13Lib_VSetPublicKeyPinSHA256:
    movem.l d2-d7/a2-a6,-(sp)
    move.l d0,-(sp)
    move.l a0,-(sp)
    jsr _AmiTLS13_SetPublicKeyPinSHA256
    addq.l #8,sp
    movem.l (sp)+,d2-d7/a2-a6
    rts

    .globl _AmiTLS13Lib_VGetLastPeerPublicKeySHA256
_AmiTLS13Lib_VGetLastPeerPublicKeySHA256:
    movem.l d2-d7/a2-a6,-(sp)
    move.l d0,-(sp)
    move.l a0,-(sp)
    jsr _AmiTLS13_GetLastPeerPublicKeySHA256
    addq.l #8,sp
    movem.l (sp)+,d2-d7/a2-a6
    rts
