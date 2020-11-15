/*
 *   Creation Date: <2004/08/28 18:38:22 greg>
 *   Time-stamp: <2004/08/28 18:38:22 greg>
 *
 *	<methods.c>
 *
 *	Misc device node methods
 *
 *   Copyright (C) 2004 Greg Watson
 *
 *   Based on MOL specific code which is
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
#include "pearpc/pearpc.h"
#include "libopenbios/ofmem.h"

/************************************************************************/
/*	RTAS (run-time abstraction services)				*/
/************************************************************************/

#ifdef CONFIG_RTAS
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
#endif


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

	printk( "%s", s );
	//vfd_draw_str( s );
        console_draw_fstr(addr, len);

	PUSH( len );
}

NODE_METHODS( video_stdout ) = {
	{ "write",	stdout_write	},
};


/************************************************************************/
/*	tty								*/
/************************************************************************/

DECLARE_NODE( tty, INSTALL_OPEN, 0, "/packages/terminal-emulator" );

/* ( addr len -- actual ) */
static void
tty_read( void )
{
	int ch, len = POP();
	char *p = (char*)POP();
	int ret=0;

	if( len > 0 ) {
		ret = 1;
		ch = getchar();
		if( ch >= 0 ) {
			*p = ch;
		} else {
			ret = 0;
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
		putchar( *p++ );
	RET( len );
}

NODE_METHODS( tty ) = {
	{ "read",	tty_read	},
	{ "write",	tty_write	},
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
}

/* ( -- ms ) */
static void
ciface_milliseconds( unsigned long args[], unsigned long ret[] )
{
	extern unsigned long get_timer_freq();
	static unsigned long mticks=0, usecs=0;
	unsigned long t;

	asm volatile("mftb %0" : "=r" (t) : );
	if( mticks )
		usecs += get_timer_freq() / 1000000 * ( t-mticks );
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
DECLARE_NODE( mmu, INSTALL_OPEN, 0, "/cpu@0" );
DECLARE_NODE( mmu_ciface, 0, 0, "/packages/client-iface" );


/* ( phys size align --- base ) */
static void
mem_claim( void )
{
	ucell align = POP();
	ucell size = POP();
	ucell phys = POP();
	ucell ret = ofmem_claim_phys( phys, size, align );

	if( ret == (ucell)-1 ) {
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
#ifdef CONFIG_RTAS
	REGISTER_NODE( rtas );
#endif
	REGISTER_NODE( video_stdout );
	REGISTER_NODE( ciface );
	REGISTER_NODE( memory );
	REGISTER_NODE( mmu );
	REGISTER_NODE( mmu_ciface );
	REGISTER_NODE( tty );
}
