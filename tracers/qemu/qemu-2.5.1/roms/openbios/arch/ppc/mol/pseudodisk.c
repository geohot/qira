/*
 *   Creation Date: <2003/11/26 16:55:47 samuel>
 *   Time-stamp: <2004/01/07 19:41:54 samuel>
 *
 *	<pseudodisk.c>
 *
 *	pseudodisk (contains files exported from linux)
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
#include "osi_calls.h"
#include "libc/string.h"
#include "libopenbios/ofmem.h"
#include "mol/prom.h"
#include "mol/mol.h"
#include "osi_calls.h"
#include "pseudofs_sh.h"

typedef struct {
	int	seekpos;
	int	fd;
	char	*myargs;
	char	*name;
	int	size;
} pdisk_data_t;


DECLARE_NODE( pdisk, INSTALL_OPEN, sizeof(pdisk_data_t), "/mol/pseudo-disk/disk" );

static void
pdisk_open( pdisk_data_t *pb )
{
	char *ep, *name = NULL;
	int part;

	pb->myargs = my_args_copy();
	/* printk("pdisk-open: %s\n", pb->myargs ); */

	part = strtol( pb->myargs, &ep, 10 );
	if( *ep ) {
		if( (name=strchr(pb->myargs, ',')) ) {
			*name = 0;
			name++;
		} else {
			name = pb->myargs;
		}
	}
	if( part )
		goto err;

	if( !name || !strlen(name) )
		pb->fd = -1;
	else {
		if( (pb->fd=PseudoFSOpen(name)) < 0 )
			goto err;
		pb->size = PseudoFSGetSize( pb->fd );
	}
	pb->name = name;
	RET( -1 );
 err:
	free( pb->myargs );
	RET(0);
}

/* ( addr len -- actual ) */
static void
pdisk_read( pdisk_data_t *pb )
{
	int len = POP();
	char *dest = (char*)POP();
	int cnt;

	if( pb->fd < 0 ) {
		memset( dest, 0, len );
		PUSH(len);
		return;
	}
	/* dest is not "mol-DMA" safe (might have a nontrivial mapping) */
	for( cnt=0; cnt<len; ) {
		char buf[2048];
		int n = MIN( len-cnt, sizeof(buf) );

		n = PseudoFSRead( pb->fd, pb->seekpos, buf, n );
		if( n <= 0 )
			break;

		memcpy( dest+cnt, buf, n );
		cnt += n;
		pb->seekpos += n;
	}
	PUSH( cnt );
}

/* ( addr len -- actual ) */
static void
pdisk_write( pdisk_data_t *pb )
{
	POP(); POP(); PUSH(-1);
	printk("pdisk write\n");
}

/* ( pos.lo pos.hi -- status ) */
static void
pdisk_seek( pdisk_data_t *pb )
{
	int pos_lo;
	POP();
	pos_lo = POP();

	if( pb->fd >= 0 ) {
		if( pos_lo == -1 )
			pos_lo = pb->size;
	}

	pb->seekpos = pos_lo;

	PUSH(0);	/* ??? */
}

/* ( -- pos.d ) */
static void
pdisk_tell( pdisk_data_t *pb )
{
	DPUSH( pb->seekpos );
}

/* ( -- cstr ) */
static void
pdisk_get_path( pdisk_data_t *pb )
{
	PUSH( (int)pb->name );
}

/* ( -- cstr ) */
static void
pdisk_get_fstype( pdisk_data_t *pb )
{
	PUSH( (int)"PSEUDO" );
}

/* ( -- cstr ) */
static void
pdisk_volume_name( pdisk_data_t *pb )
{
	PUSH( (int)"Virtual Volume" );
}

static void
pdisk_block_size( pdisk_data_t *pb )
{
	PUSH(1);
}

NODE_METHODS( pdisk ) = {
	{ "open",		pdisk_open		},
	{ "read",		pdisk_read		},
	{ "write",		pdisk_write		},
	{ "seek",		pdisk_seek		},
	{ "tell",		pdisk_tell		},
	{ "block-size",		pdisk_block_size	},
	{ "get-path",		pdisk_get_path          },
	{ "get-fstype",		pdisk_get_fstype        },
	{ "volume-name",	pdisk_volume_name	},
};

void
pseudodisk_init( void )
{
	REGISTER_NODE( pdisk );
}
