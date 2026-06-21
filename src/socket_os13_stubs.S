	.text

	.globl _amitls13_bsdsocket_socket
_amitls13_bsdsocket_socket:
	movem.l d2-d7/a2-a6,-(sp)
	move.l 48(sp),d0
	move.l 52(sp),d1
	move.l 56(sp),d2
	move.l _SocketBase,a6
	jsr -30(a6)
	movem.l (sp)+,d2-d7/a2-a6
	rts

	.globl _amitls13_bsdsocket_connect
_amitls13_bsdsocket_connect:
	movem.l d2-d7/a2-a6,-(sp)
	move.l 48(sp),d0
	move.l 52(sp),a0
	move.l 56(sp),d1
	move.l _SocketBase,a6
	jsr -54(a6)
	movem.l (sp)+,d2-d7/a2-a6
	rts

	.globl _amitls13_bsdsocket_send
_amitls13_bsdsocket_send:
	movem.l d2-d7/a2-a6,-(sp)
	move.l 48(sp),d0
	move.l 52(sp),a0
	move.l 56(sp),d1
	moveq #0,d2
	move.l _SocketBase,a6
	jsr -66(a6)
	movem.l (sp)+,d2-d7/a2-a6
	rts

	.globl _amitls13_bsdsocket_recv
_amitls13_bsdsocket_recv:
	movem.l d2-d7/a2-a6,-(sp)
	move.l 48(sp),d0
	move.l 52(sp),a0
	move.l 56(sp),d1
	moveq #0,d2
	move.l _SocketBase,a6
	jsr -78(a6)
	movem.l (sp)+,d2-d7/a2-a6
	rts

	.globl _amitls13_bsdsocket_close
_amitls13_bsdsocket_close:
	movem.l d2-d7/a2-a6,-(sp)
	move.l 48(sp),d0
	move.l _SocketBase,a6
	jsr -120(a6)
	movem.l (sp)+,d2-d7/a2-a6
	rts

	.globl _amitls13_bsdsocket_waitselect
_amitls13_bsdsocket_waitselect:
	movem.l d2-d7/a2-a6,-(sp)
	move.l 48(sp),d0
	move.l 52(sp),a0
	move.l 56(sp),a1
	move.l 60(sp),a2
	move.l 64(sp),a3
	move.l 68(sp),d1
	move.l _SocketBase,a6
	jsr -126(a6)
	movem.l (sp)+,d2-d7/a2-a6
	rts

	.globl _amitls13_bsdsocket_errno
_amitls13_bsdsocket_errno:
	movem.l d2-d7/a2-a6,-(sp)
	move.l _SocketBase,a6
	jsr -162(a6)
	movem.l (sp)+,d2-d7/a2-a6
	rts

	.globl _amitls13_bsdsocket_gethostbyname
_amitls13_bsdsocket_gethostbyname:
	movem.l d2-d7/a2-a6,-(sp)
	move.l 48(sp),a0
	move.l _SocketBase,a6
	jsr -210(a6)
	movem.l (sp)+,d2-d7/a2-a6
	rts
