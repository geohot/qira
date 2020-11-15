/*
 *   Creation Date: <2003/12/07 19:08:33 samuel>
 *   Time-stamp: <2004/01/07 19:38:36 samuel>
 *
 *	<osi-blk.c>
 *
 *	OSI-block interface
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
#include "mol/mol.h"
#include "osi_calls.h"

typedef struct {
	int	unit;
	int	channel;
} osiblk_data_t;


DECLARE_NODE( osiblk, INSTALL_OPEN, sizeof(osiblk_data_t),
	      "/pci/pci-bridge/mol-blk/disk", "/mol/mol-blk" );


static void
osiblk_open( osiblk_data_t *pb )
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
osiblk_close( osiblk_data_t *pb )
{
	selfword("close-deblocker");
}


/* ( buf blk nblks -- actual ) */
static void
osiblk_read_blocks( osiblk_data_t *pb )
{
	int i, n = POP();
	int blk = POP();
	char *dest = (char*)POP();

	/* printk("osiblk_read_blocks %x block=%d n=%d\n", (int)dest, blk, n ); */

	for( i=0; i<n; ) {
		char buf[4096];
		int m = MIN( n-i, sizeof(buf)/512 );

		if( OSI_ABlkSyncRead(pb->channel, pb->unit, blk+i, (int)buf, m*512) < 0 ) {
			printk("SyncRead: error\n");
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
osiblk_block_size( osiblk_data_t *pb )
{
	PUSH( 512 );
}

/* ( -- maxbytes ) */
static void
osiblk_max_transfer( osiblk_data_t *pb )
{
	PUSH( 1024*1024 );
}

static void
osiblk_initialize( osiblk_data_t *pb )
{
	fword("is-deblocker");
}


NODE_METHODS( osiblk ) = {
	{ NULL,			osiblk_initialize	},
	{ "open",		osiblk_open		},
	{ "close",		osiblk_close		},
	{ "read-blocks",	osiblk_read_blocks	},
	{ "block-size",		osiblk_block_size	},
	{ "max-transfer",	osiblk_max_transfer	},
};

void
osiblk_init( void )
{
	REGISTER_NODE( osiblk );
}
