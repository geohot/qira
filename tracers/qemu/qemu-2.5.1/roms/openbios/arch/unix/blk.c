/*
 *  <arch/unix/blk.c>
 *
 *	block device emulation for unix hosts
 *
 *   Copyright (C) 2004 Stefan Reinauer <stepan@openbios.org>
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   version 2
 *
 */

#include "config.h"
#include "libopenbios/bindings.h"
#include "blk.h"

typedef struct {
	int	unit;
	int	channel;
} blk_data_t;


DECLARE_NODE( blk, INSTALL_OPEN, sizeof(blk_data_t), "+/unix/block/disk" );

static void
blk_open( blk_data_t *pb )
{
	phandle_t ph;

	fword("my-unit");

	pb->unit = POP();
	pb->channel = 0;	/* FIXME */

	selfword("open-deblocker");

	/* interpose disk-label */
	ph = find_dev("/packages/disk-label");
	fword("my-args");
	PUSH_ph( ph );
	fword("interpose");

	/* printk("osi-blk: open %d\n", pb->unit ); */

	PUSH( -1 );
}

static void
blk_close( __attribute__((unused)) blk_data_t *pb )
{
	selfword("close-deblocker");
}


/* ( buf blk nblks -- actual ) */
static void
blk_read_blocks( blk_data_t *pb )
{
	cell i, n = POP();
	cell blk = POP();
	char *dest = (char*)POP();

	// printk("blk_read_blocks %x block=%d n=%d\n", (ucell)dest, blk, n );

	for( i=0; i<n; ) {
		char buf[4096];
		ucell m = MIN( n-i, sizeof(buf)/512 );

		if( read_from_disk(pb->channel, pb->unit, blk+i, (ucell)buf, m*512) < 0 ) {
			printk("read_from_disk: error\n");
			RET(0);
		}
		memcpy( dest, buf, m * 512 );
		i += m;
		dest += m * 512;
	}
	PUSH( n );
}

/* ( -- bs ) */
static void
blk_block_size( __attribute__((unused)) blk_data_t *pb )
{
	PUSH( 512 );
}

/* ( -- maxbytes ) */
static void
blk_max_transfer( __attribute__((unused)) blk_data_t *pb )
{
	PUSH( 1024*1024 );
}

static void
blk_initialize( __attribute__((unused)) blk_data_t *pb )
{
	fword("is-deblocker");
}


NODE_METHODS( blk ) = {
	{ NULL,			blk_initialize	},
	{ "open",		blk_open	},
	{ "close",		blk_close	},
	{ "read-blocks",	blk_read_blocks	},
	{ "block-size",		blk_block_size	},
	{ "max-transfer",	blk_max_transfer},
};

void
blk_init( void )
{
	REGISTER_NODE( blk );
}
