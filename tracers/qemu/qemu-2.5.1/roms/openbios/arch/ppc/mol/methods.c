/*
 *   Creation Date: <2003/10/18 13:24:29 samuel>
 *   Time-stamp: <2004/03/27 02:00:30 samuel>
 *
 *	<methods.c>
 *
 *	Misc device node methods
 *
 *   Copyright (C) 2003, 2004 Samuel Rydh (samuel@ibrium.se)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   version 2
 *
 */

#include "config.h"
#include "libopenbios/bindings.h"
#include "libc/string.h"
#include "mol/mol.h"
#include "libopenbios/ofmem.h"
#include "mol/prom.h"
#include "osi_calls.h"
#include "kbd_sh.h"

/************************************************************************/
/*	Power Management						*/
/************************************************************************/

DECLARE_NODE( powermgt, INSTALL_OPEN, 0, "/pci/pci-bridge/mac-io/power-mgt" );

/* ( -- ) */
static void
set_hybernot_flag( void )
{
}

NODE_METHODS( powermgt ) = {
	{ "set-hybernot-flag",	set_hybernot_flag	},
};


/************************************************************************/
/*	RTAS (run-time abstraction services)				*/
/************************************************************************/

DECLARE_NODE( rtas, INSTALL_OPEN, 0, "+/rtas" );

/* ( physbase -- rtas_callback ) */
static void
rtas_instantiate( void )
{
	int physbase = POP();
	int s=0x1000, size = (int)of_rtas_end - (int)of_rtas_start;
	unsigned long virt;

	while( s < size )
		s += 0x1000;
	virt = ofmem_claim_virt( 0, s, 0x1000 );
	ofmem_map( physbase, virt, s, -1 );
	memcpy( (char*)virt, of_rtas_start, size );

	printk("RTAS instantiated at %08x\n", physbase );
	flush_icache_range( (char*)virt, (char*)virt + size );

	PUSH( physbase );
}

NODE_METHODS( rtas ) = {
	{ "instantiate",	rtas_instantiate },
	{ "instantiate-rtas",	rtas_instantiate },
};



/************************************************************************/
/*	stdout								*/
/************************************************************************/

DECLARE_NODE( video_stdout, INSTALL_OPEN, 0, "Tdisplay" );

/* ( addr len -- actual ) */
static void
stdout_write( void )
{
	int len = POP();
	char *addr = (char*)POP();

	/* printk( "%s", s ); */
        console_draw_fstr(addr, len);

	PUSH( len );
}

NODE_METHODS( video_stdout ) = {
	{ "write",	stdout_write	},
};


/************************************************************************/
/*	tty								*/
/************************************************************************/

DECLARE_NODE( tty, INSTALL_OPEN, 0, "+/mol/mol-tty" );

/* ( addr len -- actual ) */
static void
tty_read( void )
{
	int ch, len = POP();
	char *p = (char*)POP();
	int ret=0;

	if( len > 0 ) {
		ret = 1;
		ch = OSI_TTYGetc();
		if( ch >= 0 ) {
			*p = ch;
		} else {
			ret = 0;
			OSI_USleep(1);
		}
	}
	PUSH( ret );
}

/* ( addr len -- actual ) */
static void
tty_write( void )
{
	int i, len = POP();
	char *p = (char*)POP();
	for( i=0; i<len; i++ )
		OSI_TTYPutc( *p++ );
	RET( len );
}

NODE_METHODS( tty ) = {
	{ "read",	tty_read	},
	{ "write",	tty_write	},
};


/************************************************************************/
/*	keyboard							*/
/************************************************************************/

typedef struct {
	int	cntrl;
	int	shift;
	int	meta;
	int	alt;
	int	save_key;
	char 	keytable[32];
} kbd_state_t;

static const unsigned char adb_ascii_table[128] =
	/* 0x00 */	"asdfhgzxcv`bqwer"
	/* 0x10 */	"yt123465=97-80]o"
	/* 0x20 */	"u[ip\nlj'k;\\,/nm."
	/* 0x30 */	"\t <\b \e          "
	/* 0x40 */	" . * +     /  - "
	/* 0x50 */	" =01234567 89   "
	/* 0x60 */	"                "
	/* 0x70 */	"                ";

static const unsigned char adb_shift_table[128] =
	/* 0x00 */	"ASDFHGZXCV~BQWER"
	/* 0x10 */	"YT!@#$^%+(&_*)}O"
	/* 0x20 */	"U{IP\nLJ\"K:|<?NM>"
	/* 0x30 */	"\t <\b \e          "
	/* 0x40 */	" . * +     /  - "
	/* 0x50 */	" =01234567 89   "
	/* 0x60 */	"                "
	/* 0x70 */	"                ";

DECLARE_NODE( kbd, INSTALL_OPEN, sizeof(kbd_state_t),
      "/psuedo-hid/keyboard",
      "/mol/mol-keyboard",
      "/mol/keyboard"
);

/* ( -- keymap ) (?) */
/* should return a pointer to an array with 32 bytes (256 bits) */
static void
kbd_get_key_map( kbd_state_t *ks )
{
	/* printk("met_kbd_get_key_map\n"); */

	/* keytable[5] = 0x40; */
	PUSH( (int)ks->keytable );
}

/* ( buf len --- actlen ) */
static void
kbd_read( kbd_state_t *ks )
{
	int ret=0, len = POP();
	char *p = (char*)POP();
	int key;

	if( !p || !len ) {
		PUSH( -1 );
		return;
	}

	if( ks->save_key ) {
		*p = ks->save_key;
		ks->save_key = 0;
		RET( 1 );
	}
	OSI_USleep(1);	/* be nice */

	for( ; (key=OSI_GetAdbKey()) >= 0 ; ) {
		int code = (key & 0x7f);
		int down = !(key & 0x80);

		if( code == 0x36 /* ctrl */ ) {
			ks->cntrl = down;
			continue;
		}
		if( code == 0x38 /* shift */ || code == 0x7b) {
			ks->shift = down;
			continue;
		}
		if( code == 0x37 /* command */ ) {
			ks->meta = down;
			continue;
		}
		if( code == 0x3a /* alt */ ) {
			ks->alt = down;
			continue;
		}
		if( !down )
			continue;

		ret = 1;
		if( ks->shift )
			key = adb_shift_table[ key & 0x7f ];
		else
			key = adb_ascii_table[ key & 0x7f ];

		if( ks->meta ) {
			ks->save_key = key;
			key = 27;
		} else if( ks->cntrl ) {
			key = key - 'a' + 1;
		}
		*p = key;
		if( !*p )
			*p = 'x';
		break;
	}
	PUSH( ret );
}

NODE_METHODS( kbd ) = {
	{ "read",		kbd_read		},
	{ "get-key-map",	kbd_get_key_map		},
};


/************************************************************************/
/*	client interface 'quiesce'					*/
/************************************************************************/

DECLARE_NODE( ciface, 0, 0, "/packages/client-iface" );

/* ( -- ) */
static void
ciface_quiesce( unsigned long args[], unsigned long ret[] )
{
#if 0
	unsigned long msr;
	/* This seems to be the correct thing to do - but I'm not sure */
	asm volatile("mfmsr %0" : "=r" (msr) : );
	msr &= ~(MSR_IR | MSR_DR);
	asm volatile("mtmsr %0" :: "r" (msr) );
#endif
	printk("=============================================================\n\n");
	prom_close();

	OSI_KbdCntrl( kKbdCntrlSuspend );
}

/* ( -- ms ) */
static void
ciface_milliseconds( unsigned long args[], unsigned long ret[] )
{
	static unsigned long mticks=0, usecs=0;
	unsigned long t;

	asm volatile("mftb %0" : "=r" (t) : );
	if( mticks )
		usecs += OSI_MticksToUsecs( t-mticks );
	mticks = t;

	PUSH( usecs/1000 );
}


NODE_METHODS( ciface ) = {
	{ "quiesce",		ciface_quiesce		},
	{ "milliseconds",	ciface_milliseconds	},
};


/************************************************************************/
/*	MMU/memory methods						*/
/************************************************************************/

DECLARE_NODE( memory, INSTALL_OPEN, 0, "/memory" );
DECLARE_NODE( mmu, INSTALL_OPEN, 0, "/cpus/@0" );
DECLARE_NODE( mmu_ciface, 0, 0, "/packages/client-iface" );


/* ( phys size align --- base ) */
static void
mem_claim( void )
{
	ucell align = POP();
	ucell size = POP();
	ucell phys = POP();
	ucell ret = ofmem_claim_phys( phys, size, align );

	if( ret == -1 ) {
		printk("MEM: claim failure\n");
		throw( -13 );
		return;
	}
	PUSH( ret );
}

/* ( phys size --- ) */
static void
mem_release( void )
{
	POP(); POP();
}

/* ( phys size align --- base ) */
static void
mmu_claim( void )
{
	ucell align = POP();
	ucell size = POP();
	ucell phys = POP();
	ucell ret = ofmem_claim_virt( phys, size, align );

	if( ret == -1 ) {
		printk("MMU: CLAIM failure\n");
		throw( -13 );
		return;
	}
	PUSH( ret );
}

/* ( phys size --- ) */
static void
mmu_release( void )
{
	POP(); POP();
}

/* ( phys virt size mode -- [ret???] ) */
static void
mmu_map( void )
{
	ucell mode = POP();
	ucell size = POP();
	ucell virt = POP();
	ucell phys = POP();
	ucell ret;

	/* printk("mmu_map: %x %x %x %x\n", phys, virt, size, mode ); */
	ret = ofmem_map( phys, virt, size, mode );

	if( ret ) {
		printk("MMU: map failure\n");
		throw( -13 );
		return;
	}
}

/* ( virt size -- ) */
static void
mmu_unmap( void )
{
	POP(); POP();
}

/* ( virt -- false | phys mode true ) */
static void
mmu_translate( void )
{
	ucell mode;
	ucell virt = POP();
	ucell phys = ofmem_translate( virt, &mode );

	if( phys == -1 ) {
		PUSH( 0 );
	} else {
		PUSH( phys );
		PUSH( mode );
		PUSH( -1 );
	}
}

/* ( virt size align -- baseaddr|-1 ) */
static void
ciface_claim( void )
{
	ucell align = POP();
	ucell size = POP();
	ucell virt = POP();
	ucell ret = ofmem_claim( virt, size, align );

	/* printk("ciface_claim: %08x %08x %x\n", virt, size, align ); */
	PUSH( ret );
}

/* ( virt size -- ) */
static void
ciface_release( void )
{
	POP();
	POP();
}


NODE_METHODS( memory ) = {
	{ "claim",		mem_claim		},
	{ "release",		mem_release		},
};

NODE_METHODS( mmu ) = {
	{ "claim",		mmu_claim		},
	{ "release",		mmu_release		},
	{ "map",		mmu_map			},
	{ "unmap",		mmu_unmap		},
	{ "translate",		mmu_translate		},
};

NODE_METHODS( mmu_ciface ) = {
	{ "cif-claim",		ciface_claim		},
	{ "cif-release",	ciface_release		},
};


/************************************************************************/
/*	init								*/
/************************************************************************/

void
node_methods_init( void )
{
	REGISTER_NODE( rtas );
	REGISTER_NODE( powermgt );
	REGISTER_NODE( kbd );
	REGISTER_NODE( video_stdout );
	REGISTER_NODE( ciface );
	REGISTER_NODE( memory );
	REGISTER_NODE( mmu );
	REGISTER_NODE( mmu_ciface );

	if( OSI_CallAvailable(OSI_TTY_GETC) )
		REGISTER_NODE( tty );

	OSI_KbdCntrl( kKbdCntrlActivate );
}
