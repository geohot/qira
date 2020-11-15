/*
 *   Creation Date: <1999/03/18 03:19:43 samuel>
 *   Time-stamp: <2003/12/26 16:58:19 samuel>
 *
 *	<os_interface.h>
 *
 *	This file includes definitions for drivers
 *	running in the "emulated" OS. (Mainly the 'sc'
 *	mechanism of communicating)
 *
 *   Copyright (C) 1999, 2000, 2001, 2002, 2003 Samuel Rydh (samuel@ibrium.se)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation
 *
 */

#ifndef _H_OSI
#define _H_OSI

/* Magic register values loaded into r3 and r4 before the 'sc' assembly instruction */
#define OSI_SC_MAGIC_R3		0x113724FA
#define OSI_SC_MAGIC_R4		0x77810F9B


/************************************************************************/
/*	Selectors (passed in r5)					*/
/************************************************************************/

#define OSI_CALL_AVAILABLE		0
#define OSI_DEBUGGER 			1	/* enter debugger */
/* obsolete OSI_LOG_STR 3 */
#define OSI_CMOUNT_DRV_VOL		4	/* conditionally mount driver volume */
/* obsolete OSI_SCSI_xxx 5-6 */
#define OSI_GET_GMT_TIME		7
#define OSI_MOUSE_CNTRL			8
#define OSI_GET_LOCALTIME		9	/* return time in secs from 01/01/04 */

#define OSI_ENET_OPEN			10
#define OSI_ENET_CLOSE			11
#define OSI_ENET_GET_ADDR		12
#define OSI_ENET_GET_STATUS		13
#define OSI_ENET_CONTROL		14
#define OSI_ENET_ADD_MULTI		16
#define OSI_ENET_DEL_MULTI		17
#define OSI_ENET_GET_PACKET		18
#define OSI_ENET_SEND_PACKET		19

#define OSI_OF_INTERFACE		20
#define OSI_OF_TRAP			21
#define OSI_OF_RTAS			22

#define OSI_SCSI_CNTRL			23
#define OSI_SCSI_SUBMIT			24
#define OSI_SCSI_ACK			25

#define OSI_GET_MOUSE			26	/* -- r3 status, r4-r8 mouse data */
#define OSI_ACK_MOUSE_IRQ		27	/* -- int */

#define OSI_SET_VMODE			28	/* modeID, depth -- error */
#define OSI_GET_VMODE_INFO		29	/* mode, depth -- r3 status, r4-r9 pb */
#define OSI_GET_MOUSE_DPI		30	/* -- mouse_dpi */

#define OSI_SET_VIDEO_POWER		31
#define OSI_GET_FB_INFO			32	/* void -- r3 status, r4-r8 video data */

#define OSI_SOUND_WRITE			33
/* #define OSI_SOUND_FORMAT 34 */
#define OSI_SOUND_SET_VOLUME		35
#define OSI_SOUND_CNTL			36
/* obsolete OSI_SOUND call 37 */

#define OSI_VIDEO_ACK_IRQ		38
#define OSI_VIDEO_CNTRL			39

#define OSI_SOUND_IRQ_ACK		40
#define OSI_SOUND_START_STOP		41

#define OSI_REGISTER_IRQ		42	/* reg_property[0] appl_int -- irq_cookie */
/* obsolete OSI_IRQ 43-46 */

#define OSI_LOG_PUTC			47	/* char -- */

#define OSI_KBD_CNTRL			50
#define OSI_GET_ADB_KEY			51	/* -- adb_keycode (keycode | keycode_id in r4) */

#define OSI_WRITE_NVRAM_BYTE		52	/* offs, byte -- */
#define OSI_READ_NVRAM_BYTE		53	/* offs -- byte */

#define OSI_EXIT			54

#define OSI_KEYCODE_TO_ADB		55	/* (keycode | keycode_id) -- adb_keycode */
#define OSI_MAP_ADB_KEY			56	/* keycode, adbcode -- */
#define OSI_SAVE_KEYMAPPING		57	/* -- */
#define OSI_USLEEP			58	/* usecs -- */
#define OSI_SET_COLOR			59	/* index value -- */

#define OSI_PIC_MASK_IRQ		60	/* irq -- */
#define OSI_PIC_UNMASK_IRQ		61	/* irq -- */
#define OSI_PIC_ACK_IRQ			62	/* irq mask_flag -- */
#define OSI_PIC_GET_ACTIVE_IRQ		63

#define OSI_GET_COLOR			64	/* index -- value */

/* 65-67 old ablk implementation */
#define OSI_IRQTEST			65

#define OSI_ENET2_OPEN			68
#define OSI_ENET2_CLOSE			69
#define OSI_ENET2_CNTRL			70
#define OSI_ENET2_RING_SETUP		71
#define OSI_ENET2_KICK			72
#define OSI_ENET2_GET_HWADDR		73
#define OSI_ENET2_IRQ_ACK		74

#define OSI_PROM_IFACE			76
#define  kPromClose		0
#define  kPromPeer		1
#define  kPromChild		2
#define  kPromParent		3
#define  kPromPackageToPath	4
#define  kPromGetPropLen	5
#define  kPromGetProp		6
#define  kPromNextProp		7
#define  kPromSetProp		8
#define  kPromChangePHandle	9

#define OSI_PROM_PATH_IFACE		77
#define  kPromCreateNode	16
#define  kPromFindDevice	17

#define OSI_BOOT_HELPER			78
#define  kBootHAscii2Unicode	32
#define  kBootHUnicode2Ascii	33
#define  kBootHGetStrResInd	34		/* key, buf, len -- buf */
#define  kBootHGetRAMSize	35		/* -- ramsize */

#define OSI_ABLK_RING_SETUP		79
#define OSI_ABLK_CNTRL			80
#define OSI_ABLK_DISK_INFO		81
#define OSI_ABLK_KICK			82
#define OSI_ABLK_IRQ_ACK		83
#define OSI_ABLK_SYNC_READ		84
#define OSI_ABLK_SYNC_WRITE		85
#define OSI_ABLK_BLESS_DISK		86

#define OSI_EMUACCEL			89	/* EMULATE_xxx, nip -- index */
#define OSI_MAPIN_MREGS			90	/* mphys */
#define OSI_NVRAM_SIZE			91

#define OSI_MTICKS_TO_USECS		92
#define OSI_USECS_TO_MTICKS		93

/* obsolete OSI_BLK 94-95 */

#define OSI_PSEUDO_FS			96
#define  kPseudoFSOpen		1
#define  kPseudoFSClose		2
#define  kPseudoFSGetSize	3
#define  kPseudoFSRead		4
#define  kPseudoFSIndex2Name	5

#define OSI_TTY_PUTC			97
#define OSI_TTY_GETC			98
#define OSI_TTY_IRQ_ACK			99

#define NUM_OSI_SELECTORS		100	/* remember to increase this... */

#endif   /* _H_OSI */
