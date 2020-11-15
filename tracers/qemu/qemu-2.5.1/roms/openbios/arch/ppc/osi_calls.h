/*
 *   Creation Date: <2002/06/16 01:40:57 samuel>
 *   Time-stamp: <2003/12/26 17:02:09 samuel>
 *
 *	<osi_calls.h>
 *
 *	OSI call inlines
 *
 *   Copyright (C) 2002, 2003 Samuel Rydh (samuel@ibrium.se)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation
 *
 */

#ifndef _H_OSI_CALLS
#define _H_OSI_CALLS

#include "osi.h"

/* Old gcc versions have a limit on the number of registers used.
 * Newer gcc versions (gcc 3.3) require that the clobber list does
 * not overlap declared registers.
 */
#if __GNUC__ == 2 || ( __GNUC__ == 3 && __GNUC_MINOR__ < 3 )
#define SHORT_REGLIST
#endif


/************************************************************************/
/*	OSI call instantiation macros					*/
/************************************************************************/

#define dreg(n)			__oc_##n __asm__ (#n)
#define ir(n)			"r" (__oc_##n)
#define rr(n)			"=r" (__oc_##n)

#define _oc_head( input_regs... )				\
{								\
	int _ret=0;						\
	{							\
		register unsigned long dreg(r3);		\
		register unsigned long dreg(r4);		\
		register unsigned long dreg(r5)			\
			,##input_regs ;

#define _oc_syscall( number, extra_ret_regs... )		\
		__oc_r3 = OSI_SC_MAGIC_R3;			\
		__oc_r4 = OSI_SC_MAGIC_R4;			\
		__oc_r5 = number;				\
		__asm__ __volatile__ (				\
		  "sc	" : rr(r3) ,## extra_ret_regs

#define _oc_input( regs... )					\
		: ir(r3), ir(r4), ir(r5)			\
		, ## regs					\
		: "memory" );

/* the tail memory clobber is necessary since we violate the strict
 * aliasing rules when we return structs through the registers.
 */
#define _oc_tail						\
		asm volatile ( "" : : : "memory" );		\
		_ret = __oc_r3;					\
	}							\
	return _ret;						\
}


/************************************************************************/
/*	Alternatives 							*/
/************************************************************************/

#ifdef SHORT_REGLIST
#define _oc_syscall_r10w6( number, inputregs... )		\
		__oc_r3 = OSI_SC_MAGIC_R3;			\
		__oc_r4 = OSI_SC_MAGIC_R4;			\
		__oc_r5 = number;				\
		__asm__ __volatile__ (				\
		  "sc			\n"			\
		  "stw	4,0(10) 	\n"			\
		  "stw	5,4(10) 	\n"			\
		  "stw	6,8(10) 	\n"			\
		  "stw	7,12(10) 	\n"			\
		  "stw	8,16(10) 	\n"			\
		  "stw	9,20(10) 	\n"			\
		: rr(r3)					\
		: ir(r3), ir(r4), ir(r5), ir(r10) 		\
		  ,## inputregs 				\
		: "memory",					\
		   "r4", "r5", "r6", "r7", "r8", "r9" );
#endif


/************************************************************************/
/*	Common helper functions						*/
/************************************************************************/

#define _osi_call0( type, name, number ) 			\
type name( void ) 						\
	_oc_head()						\
	_oc_syscall( number )					\
	_oc_input()						\
	_oc_tail

#define _osi_call1( type, name, number, type1, arg1 ) 		\
type name( type1 arg1 ) 					\
	_oc_head( dreg(r6) )					\
	__oc_r6 = (unsigned long)arg1;				\
	_oc_syscall( number )					\
	_oc_input( ir(r6) )					\
	_oc_tail

#define _osi_call2( type, name, number, t1, a1, t2, a2 ) 	\
type name( t1 a1, t2 a2 ) 					\
	_oc_head( dreg(r6), dreg(r7) )				\
	__oc_r6 = (unsigned long)a1;				\
	__oc_r7 = (unsigned long)a2;				\
	_oc_syscall( number )					\
	_oc_input( ir(r6), ir(r7) )				\
	_oc_tail

#define _osi_call3( type, name, number, t1, a1, t2, a2, t3, a3 ) \
type name( t1 a1, t2 a2, t3 a3 ) 				\
	_oc_head( dreg(r6), dreg(r7), dreg(r8) )		\
	__oc_r6 = (unsigned long)a1;				\
	__oc_r7 = (unsigned long)a2;				\
	__oc_r8 = (unsigned long)a3;				\
	_oc_syscall( number )					\
	_oc_input( ir(r6), ir(r7), ir(r8) )			\
	_oc_tail

#define _osi_call4( type, name, number, t1, a1, t2, a2, t3, a3, t4, a4 ) \
type name( t1 a1, t2 a2, t3 a3, t4 a4 ) 			\
	_oc_head( dreg(r6), dreg(r7), dreg(r8), dreg(r9) )	\
	__oc_r6 = (unsigned long)a1;				\
	__oc_r7 = (unsigned long)a2;				\
	__oc_r8 = (unsigned long)a3;				\
	__oc_r9 = (unsigned long)a4;				\
	_oc_syscall( number )					\
	_oc_input( ir(r6), ir(r7), ir(r8), ir(r9) )		\
	_oc_tail

#define _osi_call5( type, name, number, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5 ) \
type name( t1 a1, t2 a2, t3 a3, t4 a4, t5 a5 ) 				\
	_oc_head( dreg(r6), dreg(r7), dreg(r8), dreg(r9), dreg(r10) )	\
	__oc_r6 = (unsigned long)a1;					\
	__oc_r7 = (unsigned long)a2;					\
	__oc_r8 = (unsigned long)a3;					\
	__oc_r9 = (unsigned long)a4;					\
	__oc_r10 = (unsigned long)a5;					\
	_oc_syscall( number )						\
	_oc_input( ir(r6), ir(r7), ir(r8), ir(r9), ir(r10) )		\
	_oc_tail

#define _osi_call6( type, name, number, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5, t6, a6 ) \
type name( t1 a1, t2 a2, t3 a3, t4 a4, t5 a5, t6 a6 ) 				\
	_oc_head( dreg(r6), dreg(r7), dreg(r8), dreg(r9), dreg(r10), dreg(r11) )\
	__oc_r6 = (unsigned long)a1;					\
	__oc_r7 = (unsigned long)a2;					\
	__oc_r8 = (unsigned long)a3;					\
	__oc_r9 = (unsigned long)a4;					\
	__oc_r10 = (unsigned long)a5;					\
	__oc_r11 = (unsigned long)a6;					\
	_oc_syscall( number )						\
	_oc_input( ir(r6), ir(r7), ir(r8), ir(r9), ir(r10), ir(r11) )	\
	_oc_tail


/************************************************************************/
/*	Special 							*/
/************************************************************************/

/* r4 returned in retarg1 pointer */
#define _osi_call0_w1( type, name, number, type1, retarg1 ) 	\
type name( type1 retarg1 ) 					\
	_oc_head()						\
	_oc_syscall( number, rr(r4) )				\
	_oc_input()						\
	*retarg1 = __oc_r4;					\
	_oc_tail

#define _osi_call0_w2( type, name, number, type1, retarg1 ) 	\
type name( type1 retarg1 ) 					\
	_oc_head()						\
	_oc_syscall( number, rr(r4), rr(r5) )			\
	_oc_input()						\
	((unsigned long*)retarg1)[0] = __oc_r4;			\
	((unsigned long*)retarg1)[1] = __oc_r5;			\
	_oc_tail

/* r4-r8 returned in retarg1 pointer */
#define _osi_call0_w5( type, name, number, type1, retarg1 ) 	\
type name( type1 retarg1 ) 					\
	_oc_head( dreg(r6), dreg(r7), dreg(r8) )		\
	_oc_syscall( number, 					\
		rr(r4), rr(r5), rr(r6), rr(r7), rr(r8) )	\
	_oc_input()						\
	((unsigned long*)retarg1)[0] = __oc_r4;			\
	((unsigned long*)retarg1)[1] = __oc_r5;			\
	((unsigned long*)retarg1)[2] = __oc_r6;			\
	((unsigned long*)retarg1)[3] = __oc_r7;			\
	((unsigned long*)retarg1)[4] = __oc_r8;			\
	_oc_tail

/* r4 returned in retarg pointer */
#define _osi_call1_w1( type, name, number, t1, a1, t2, retarg ) \
type name( t1 a1, t2 retarg ) 					\
	_oc_head( dreg(r6) )					\
	__oc_r6 = (unsigned long)a1;				\
	_oc_syscall( number, rr(r4) )				\
	_oc_input( ir(r6) )					\
	((unsigned long*)retarg)[0] = __oc_r4;			\
	_oc_tail

/* r4,r5 returned in retarg1, retarg2 */
#define _osi_call1_w1w1( type, name, number, t1, a1, t2, retarg1, t3, retarg2 ) \
type name( t1 a1, t2 retarg1, t3 retarg2 )			\
	_oc_head( dreg(r6) )					\
	__oc_r6 = (unsigned long)a1;				\
	_oc_syscall( number, rr(r4), rr(r5) )			\
	_oc_input( ir(r6) )					\
	((unsigned long*)retarg1)[0] = __oc_r4;			\
	((unsigned long*)retarg2)[0] = __oc_r5;			\
	_oc_tail

/* r4,r5 returned in retarg1, retarg2, retarg3 */
#define _osi_call1_w1w1w1( type, name, number, t1, a1, t2, retarg1, t3, retarg2, t4, retarg3 ) \
type name( t1 a1, t2 retarg1, t3 retarg2, t4 retarg3 )		\
	_oc_head( dreg(r6) )					\
	__oc_r6 = (unsigned long)a1;				\
	_oc_syscall( number, rr(r4), rr(r5), rr(r6) )		\
	_oc_input( ir(r6) )					\
	((unsigned long*)retarg1)[0] = __oc_r4;			\
	((unsigned long*)retarg2)[0] = __oc_r5;			\
	((unsigned long*)retarg3)[0] = __oc_r6;			\
	_oc_tail

/* r4,r5 returned in retarg pointer */
#define _osi_call1_w2( type, name, number, t1, a1, t2, retarg ) \
type name( t1 a1, t2 retarg ) 					\
	_oc_head( dreg(r6) )					\
	__oc_r6 = (unsigned long)a1;				\
	_oc_syscall( number, rr(r4), rr(r5) )			\
	_oc_input( ir(r6) )					\
	((unsigned long*)retarg)[0] = __oc_r4;			\
	((unsigned long*)retarg)[1] = __oc_r5;			\
	_oc_tail

/* r4-r7 returned in retarg pointer */
#define _osi_call1_w4( type, name, number, t1, a1, t2, retarg ) \
type name( t1 a1, t2 retarg )					\
	_oc_head( dreg(r6), dreg(r7) )				\
	__oc_r6 = (unsigned long)a1;				\
	_oc_syscall( number, rr(r4), rr(r5), rr(r6), rr(r7) )	\
	_oc_input( ir(r6) )					\
	((unsigned long*)retarg)[0] = __oc_r4;			\
	((unsigned long*)retarg)[1] = __oc_r5;			\
	((unsigned long*)retarg)[2] = __oc_r6;			\
	((unsigned long*)retarg)[3] = __oc_r7;			\
	_oc_tail


/* r4-r5 returned in retarg pointer */
#define _osi_call2_w2( type, name, number, t1, a1, t2, a2, t3, retarg ) \
type name( t1 a1, t2 a2, t3 retarg ) 				\
	_oc_head( dreg(r6), dreg(r7) )				\
	__oc_r6 = (unsigned long)a1;				\
	__oc_r7 = (unsigned long)a2;				\
	_oc_syscall( number, rr(r4), rr(r5) )			\
	_oc_input( ir(r6), ir(r7) )				\
	((unsigned long*)retarg)[0] = __oc_r4;			\
	((unsigned long*)retarg)[1] = __oc_r5;			\
	_oc_tail

/* r4-r7 returned in retarg pointer */
#define _osi_call2_w4( type, name, number, t1, a1, t2, a2, t3, retarg ) \
type name( t1 a1, t2 a2, t3 retarg ) 				\
	_oc_head( dreg(r6), dreg(r7) )				\
	__oc_r6 = (unsigned long)a1;				\
	__oc_r7 = (unsigned long)a2;				\
	_oc_syscall( number, rr(r4), rr(r5), rr(r6), rr(r7) )	\
	_oc_input( ir(r6), ir(r7) )				\
	((unsigned long*)retarg)[0] = __oc_r4;			\
	((unsigned long*)retarg)[1] = __oc_r5;			\
	((unsigned long*)retarg)[2] = __oc_r6;			\
	((unsigned long*)retarg)[3] = __oc_r7;			\
	_oc_tail

#ifdef SHORT_REGLIST
/* r4-r9 returned in retarg pointer */
#define _osi_call2_w6( type, name, number, t1, a1, t2, a2, t3, retarg ) \
type name( t1 a1, t2 a2, t3 retarg ) 				\
	_oc_head( dreg(r6), dreg(r7), dreg(r10) )		\
        __oc_r6 = (unsigned long)a1;				\
        __oc_r7 = (unsigned long)a2;				\
	__oc_r10 = (unsigned long)retarg;			\
	_oc_syscall_r10w6( number, ir(r6), ir(r7) )		\
	_oc_tail

#else /* SHORT_REGLIST */

/* r4-r9 returned in retarg pointer */
#define _osi_call2_w6( type, name, number, t1, a1, t2, a2, t3, retarg ) \
type name( t1 a1, t2 a2, t3 retarg ) 				\
	_oc_head( dreg(r6), dreg(r7), dreg(r8), dreg(r9) )	\
	__oc_r6 = (unsigned long)a1;				\
	__oc_r7 = (unsigned long)a2;				\
	_oc_syscall( number, rr(r4), rr(r5), rr(r6), rr(r7), rr(r8), rr(r9) )	\
	_oc_input( ir(r6), ir(r7) )				\
	((unsigned long*)retarg)[0] = __oc_r4;			\
	((unsigned long*)retarg)[1] = __oc_r5;			\
	((unsigned long*)retarg)[2] = __oc_r6;			\
	((unsigned long*)retarg)[3] = __oc_r7;			\
	((unsigned long*)retarg)[4] = __oc_r8;			\
	((unsigned long*)retarg)[5] = __oc_r9;			\
	_oc_tail

#endif /* SHORT_REGLIST */


/************************************************************************/
/*	OSI call inlines						*/
/************************************************************************/

static inline _osi_call1( int, OSI_CallAvailable, OSI_CALL_AVAILABLE, int, osi_num );

static inline _osi_call1( int, OSI_PutC, OSI_LOG_PUTC, int, ch );

static inline _osi_call1( int, OSI_Debugger, OSI_DEBUGGER, int, num );
static inline _osi_call0( int, OSI_Exit, OSI_EXIT );

/* misc */
static inline _osi_call0( unsigned long, OSI_GetLocalTime, OSI_GET_LOCALTIME );
static inline _osi_call0( unsigned long, OSI_GetGMTTime, OSI_GET_GMT_TIME );
static inline _osi_call1( int, OSI_USleep, OSI_USLEEP, int, usecs );

/* NVRAM */
static inline _osi_call0( int, OSI_NVRamSize, OSI_NVRAM_SIZE );
static inline _osi_call1( int, OSI_ReadNVRamByte, OSI_READ_NVRAM_BYTE, int, offs );
static inline _osi_call2( int, OSI_WriteNVRamByte, OSI_WRITE_NVRAM_BYTE, int, offs,
			  unsigned char, ch );

/* keyboard stuff */
static inline _osi_call0_w1( int, OSI_GetAdbKey2, OSI_GET_ADB_KEY, int *, raw_key );
static inline _osi_call1( int, OSI_KbdCntrl, OSI_KBD_CNTRL, int, cmd );

static inline int OSI_GetAdbKey( void )
	{ int dummy_raw_key; return OSI_GetAdbKey2( &dummy_raw_key ); }
static inline _osi_call2( int, OSI_MapAdbKey, OSI_MAP_ADB_KEY, int, keycode, int, adbkey )
static inline _osi_call1( int, OSI_KeycodeToAdb, OSI_KEYCODE_TO_ADB, int, keycode );
static inline _osi_call0( int, OSI_SaveKeymapping, OSI_SAVE_KEYMAPPING );

/* mouse support */
struct osi_mouse;
static inline _osi_call0_w5( int, OSI_GetMouse, OSI_GET_MOUSE, struct osi_mouse *, ret );
static inline _osi_call0( int, OSI_GetMouseDPI, OSI_GET_MOUSE_DPI );

/* video */
static inline _osi_call2( int, OSI_SetVMode_, OSI_SET_VMODE, int, mode, int, depth_mode );
struct osi_get_vmode_info;
static inline _osi_call2_w6( int, OSI_GetVModeInfo_, OSI_GET_VMODE_INFO, int, mode, int, depth_mode,
			     struct osi_get_vmode_info *, ret );
static inline _osi_call1( int, OSI_SetVPowerState, OSI_SET_VIDEO_POWER, int, power_state );
static inline _osi_call2( int, OSI_SetColor, OSI_SET_COLOR, int, index, int, rgb );
static inline _osi_call0_w1( int, OSI_VideoAckIRQ, OSI_VIDEO_ACK_IRQ, int *, events );

static inline void OSI_RefreshPalette( void ) { OSI_SetColor(-1,0); }

/* PIC (mac-io replacement) */
static inline _osi_call1( int, OSI_PICMaskIRQ, OSI_PIC_MASK_IRQ, int, irq );
static inline _osi_call1( int, OSI_PICUnmaskIRQ, OSI_PIC_UNMASK_IRQ, int, irq );
static inline _osi_call2( int, OSI_PICAckIRQ, OSI_PIC_ACK_IRQ, int, irq, int, mask_it );
static inline _osi_call0( int, OSI_PICGetActiveIRQ, OSI_PIC_GET_ACTIVE_IRQ );

/* sound */
static inline _osi_call1( int, OSI_SoundCntl, OSI_SOUND_CNTL, int, cmd );
static inline _osi_call2( int, OSI_SoundCntl1, OSI_SOUND_CNTL, int, cmd, int, p1 );
static inline _osi_call3( int, OSI_SoundCntl2, OSI_SOUND_CNTL, int, cmd, int, p1, int, p2 );
static inline _osi_call0_w2( int, OSI_SoundIRQAck, OSI_SOUND_IRQ_ACK, unsigned long *, timestamp );
static inline _osi_call3( int, OSI_SoundWrite, OSI_SOUND_WRITE, int, physbuf, int, len, int, restart );
static inline _osi_call3( int, OSI_SoundSetVolume, OSI_SOUND_SET_VOLUME, int, hwvol, int, speakervol, int, mute );

/* async block driver */
struct ablk_disk_info;
static inline _osi_call2_w4( int, OSI_ABlkDiskInfo, OSI_ABLK_DISK_INFO, int, channel, int, unit,
			     struct ablk_disk_info *, retinfo );
static inline _osi_call1( int, OSI_ABlkKick, OSI_ABLK_KICK, int, channel );
static inline _osi_call1_w1w1w1( int, OSI_ABlkIRQAck, OSI_ABLK_IRQ_ACK, int, channel, int *, req_count,
			       int *, active, int *, events );
static inline _osi_call3( int, OSI_ABlkRingSetup, OSI_ABLK_RING_SETUP, int, channel, int, mphys, int, n_el );
static inline _osi_call2( int, OSI_ABlkCntrl, OSI_ABLK_CNTRL, int, channel, int, cmd );
static inline _osi_call3( int, OSI_ABlkCntrl1, OSI_ABLK_CNTRL, int, channel, int, cmd, int, param );
static inline _osi_call5( int, OSI_ABlkSyncRead, OSI_ABLK_SYNC_READ, int, channel, int, unit,
			  int, blk, unsigned long, mphys, int, size );
static inline _osi_call5( int, OSI_ABlkSyncWrite, OSI_ABLK_SYNC_WRITE, int, channel, int, unit,
			  int, blk, unsigned long, mphys, int, size );
static inline _osi_call2( int, OSI_ABlkBlessDisk, OSI_ABLK_BLESS_DISK, int, channel, int, unit );

static inline _osi_call0( int, OSI_CMountDrvVol, OSI_CMOUNT_DRV_VOL );

/* enet2 */
static inline _osi_call0( int, OSI_Enet2Open, OSI_ENET2_OPEN );
static inline _osi_call0( int, OSI_Enet2Close, OSI_ENET2_CLOSE );
static inline _osi_call3( int, OSI_Enet2RingSetup, OSI_ENET2_RING_SETUP, int, which_ring,
			  int, ring_mphys, int, n_el );
static inline _osi_call2( int, OSI_Enet2Cntrl1, OSI_ENET2_CNTRL, int, cmd, int, param );
static inline _osi_call1( int, OSI_Enet2Cntrl, OSI_ENET2_CNTRL, int, cmd );
static inline _osi_call0( int, OSI_Enet2Kick, OSI_ENET2_KICK );

static inline _osi_call0_w2( int, OSI_Enet2GetHWAddr__, OSI_ENET2_GET_HWADDR, unsigned long *, retbuf );
static inline int OSI_Enet2GetHWAddr( unsigned char *addr ) {
	int ret;
	unsigned long buf[2];

	ret = OSI_Enet2GetHWAddr__( buf );

	((unsigned long*)addr)[0] = buf[0];
	((unsigned short*)addr)[2] = (buf[1] >> 16);
	return ret;
}
static inline _osi_call2( int, OSI_Enet2IRQAck, OSI_ENET2_IRQ_ACK, int, irq_enable, int, rx_head );

/* PROM (device-tree) */
static inline _osi_call2( int, OSI_PromIface, OSI_PROM_IFACE, int, what, int, ph );
static inline _osi_call3( int, OSI_PromIface1, OSI_PROM_IFACE, int, what, int, ph, int, p1 );
static inline _osi_call4( int, OSI_PromIface2, OSI_PROM_IFACE, int, what, int, ph, int, p1, int, p2 );
static inline _osi_call5( int, OSI_PromIface3, OSI_PROM_IFACE, int, what, int, ph, int, p1, int, p2, int, p3 );
static inline _osi_call2( int, OSI_PromPathIface, OSI_PROM_PATH_IFACE, int, what, const char *, p );

/* emulation acceleration */
static inline _osi_call1( int, OSI_MapinMregs, OSI_MAPIN_MREGS, unsigned long, mphys );
static inline _osi_call3( int, OSI_EmuAccel, OSI_EMUACCEL, int, emuaccel_flags, int, param, int, inst_addr );

/* timer frequency */
static inline _osi_call1( int, OSI_MticksToUsecs, OSI_MTICKS_TO_USECS, unsigned long, mticks );
static inline _osi_call1( int, OSI_UsecsToMticks, OSI_USECS_TO_MTICKS, unsigned long, usecs );

/* fb info */
struct osi_fb_info;
static inline _osi_call0_w5( int, OSI_GetFBInfo, OSI_GET_FB_INFO, struct osi_fb_info *, retinfo );

/* SCSI */
static inline _osi_call0( int, OSI_SCSIAck, OSI_SCSI_ACK );
static inline _osi_call1( int, OSI_SCSISubmit, OSI_SCSI_SUBMIT, int, req_mphys );
static inline _osi_call2( int, OSI_SCSIControl, OSI_SCSI_CNTRL, int, sel, int, param );

/* TTY */
static inline _osi_call0( int, OSI_TTYGetc, OSI_TTY_GETC );
static inline _osi_call1( int, OSI_TTYPutc, OSI_TTY_PUTC, int, ch );
static inline _osi_call0( int, OSI_TTYIRQAck, OSI_TTY_IRQ_ACK );

#endif   /* _H_OSI_CALLS */
