/*
 *   Creation Date: <2002/01/13 13:53:14 samuel>
 *   Time-stamp: <2002/01/27 19:56:11 samuel>
 *
 *	<mmutypes.h>
 *
 *	MMU definitions
 *
 *   Most of these declarations originate from the Linux Kernel
 *
 *   Copyright (C) 2002 Samuel Rydh (samuel@ibrium.se)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation
 *
 */

#ifndef _H_MMUTYPES
#define _H_MMUTYPES

/* Hardware Page Table Entry */
typedef struct mPTE {
	unsigned long v:1;	/* Entry is valid */
	unsigned long vsid:24;	/* Virtual segment identifier */
	unsigned long h:1;	/* Hash algorithm indicator */
	unsigned long api:6;	/* Abbreviated page index */

	unsigned long rpn:20;	/* Real (physical) page number */
	unsigned long    :3;	/* Unused */
	unsigned long r:1;	/* Referenced */
	unsigned long c:1;	/* Changed */
	unsigned long w:1;	/* Write-thru cache mode */
	unsigned long i:1;	/* Cache inhibited */
	unsigned long m:1;	/* Memory coherence */
	unsigned long g:1;	/* Guarded */
	unsigned long  :1;	/* Unused */
	unsigned long pp:2;	/* Page protection */
} mPTE_t;

typedef struct mPTE_64 {
	uint32_t avpn_low;	/* Abbreviated Virtual Page Number (unused) */
	uint32_t avpn:25;	/* Abbreviated Virtual Page Number */
	uint32_t sw:4;		/* Software Use */
	uint32_t  :1;		/* Reserved */
	uint32_t h:1;		/* Hash algorithm indicator */
	uint32_t v:1;		/* Entry is valid */

	uint32_t rpn_low;	/* Real (physical) page number (unused) */
	uint32_t rpn:20;	/* Real (physical) page number */
	uint32_t    :2;		/* Reserved */
	uint32_t ac:1;		/* Address Compare*/
	uint32_t r:1;		/* Referenced */
	uint32_t c:1;		/* Changed */
	uint32_t w:1;		/* Write-thru cache mode */
	uint32_t i:1;		/* Cache inhibited */
	uint32_t m:1;		/* Memory coherence */
	uint32_t g:1;		/* Guarded */
	uint32_t n:1;		/* No-Execute */
	uint32_t pp:2;		/* Page protection */
} mPTE_64_t;

typedef struct _mBATU {		/* Upper part of BAT (all except 601) */
        unsigned long bepi:15;	/* Effective page index (virtual address) */
        unsigned long :4;	/* Unused */
        unsigned long bl:11;	/* Block size mask */
        unsigned long vs:1;	/* Supervisor valid */
        unsigned long vp:1;	/* User valid */
} mBATU;

typedef struct _mBATL {		/* Lower part of BAT (all except 601) */
        unsigned long brpn:15;	/* Real page index (physical address) */
        unsigned long :10;	/* Unused */
        unsigned long w:1;	/* Write-thru cache */
        unsigned long i:1;	/* Cache inhibit */
        unsigned long m:1;	/* Memory coherence */
        unsigned long g:1;	/* Guarded (MBZ in IBAT) */
        unsigned long :1;	/* Unused */
        unsigned long pp:2;	/* Page access protections */
} mBATL;

typedef struct _mBAT {
        mBATU batu;		/* Upper register */
        mBATL batl;		/* Lower register */
} mBAT;

typedef struct _mSEGREG {
        unsigned long t:1;      /* Normal or I/O  type */
        unsigned long ks:1;     /* Supervisor 'key' (normally 0) */
        unsigned long kp:1;     /* User 'key' (normally 1) */
        unsigned long n:1;      /* No-execute */
        unsigned long :4;       /* Unused */
        unsigned long vsid:24;  /* Virtual Segment Identifier */
} mSEGREG;


#endif   /* _H_MMUTYPES */
