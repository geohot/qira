/*
 *   Creation Date: <2003/12/03 21:20:58 samuel>
 *   Time-stamp: <2004/01/07 19:34:50 samuel>
 *
 *	<deblocker.c>
 *
 *	deblocker implementation
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
#include "libc/diskio.h"
#include "packages.h"

typedef struct {
        ucell   mark_hi, mark_lo;
	xt_t	read_xt;
	xt_t	write_xt;

	int	max_xfer;
	int	blksize;
	char	*buf;
} deblk_info_t;

DECLARE_NODE( deblocker, 0, sizeof(deblk_info_t), "+/packages/deblocker" );

/* ( -- flag ) */
static void
deblk_open( deblk_info_t *di )
{
	xt_t xt;

	di->read_xt = find_parent_method("read-blocks");
	di->write_xt = find_parent_method("write-blocks");

	if( !di->read_xt )
		RET(0);

	di->blksize = di->max_xfer = 512;
	if( (xt=find_parent_method("block-size")) ) {
		call_parent( xt );
		di->blksize = POP();
	}
	if( (xt=find_parent_method("max-transfer")) ) {
		call_parent( xt );
		di->max_xfer = POP();
	}
	/* printk("block-size: %x max_xfer: %x read_xt %x write_xt %x\n",
	   di->blksize, di->max_xfer, di->write_xt, di->read_xt ); */

	di->buf = malloc( di->blksize );
	PUSH(-1);
}

/* ( -- ) */
static void
deblk_close( deblk_info_t *di )
{
	free( di->buf );
}

/* ( pos_lo pos_hi -- status ) */
static void
deblk_seek( deblk_info_t *di )
{
	ucell pos_hi = POP();
	ucell pos_lo = POP();
	ducell mark = ((ducell)pos_hi << BITS) | pos_lo;

	/* printk("deblk_seek %x %08x\n", pos_hi, pos_lo ); */

	/* -1 means seek to EOF (at least in our implementation) */
	if( (dcell)mark == -1 )
		RET(-1);
        di->mark_hi = pos_hi;
        di->mark_lo = pos_lo;

	/* 0,1 == success, -1 == error */
	PUSH(0);
}

/* ( -- mark.d ) */
static void
deblk_tell( deblk_info_t *di )
{
	PUSH( di->mark_lo );
	PUSH( di->mark_hi );
}


#define DO_IO( xt, buf, blk, n )	\
	({ PUSH3(pointer2cell(buf), blk, n); call_parent(xt); POP(); })

typedef struct {
	/* block operation */
	char	*blk_buf;
	int	nblks;

	/* byte operation */
	cell	offs;
	int	len;
	char	*data;		/* start of data */
} work_t;

static void
split( deblk_info_t *di, char *data, int len, work_t w[3] )
{
	ducell mark = ((ducell)di->mark_hi << BITS) | di->mark_lo;
	memset( w, 0, sizeof(work_t[3]) );

	w[0].offs = mark % di->blksize;
	w[0].blk_buf = di->buf;
	w[0].data = data;
	if( w[0].offs ) {
		w[0].len = MIN( len, di->blksize - w[0].offs );
		w[0].nblks = w[0].len ? 1:0;
		data += w[0].len;
		len -= w[0].len;
	}

	w[1].blk_buf = data;
	w[1].nblks = (len / di->blksize);
	w[1].len = w[1].nblks * di->blksize;
	data += w[1].len;
	len -= w[1].len;

	w[2].blk_buf = di->buf;
	w[2].data = data;
	w[2].len = len;
	w[2].nblks = len ? 1:0;
}

static int
do_readwrite( deblk_info_t *di, int is_write, xt_t xt )
{
	int blk, i, n, len = POP();
	char *dest = (char*)cell2pointer(POP());
	int last=0, retlen=0;
	work_t w[3];
	ducell mark = ((ducell)di->mark_hi << BITS) | di->mark_lo;

	/* printk("read: %x %x\n", (int)dest, len ); */

	if( !xt )
		return -1;

	blk = mark / di->blksize;
	split( di, dest, len, w );

	for( i=0; !last && i<3; i++ ) {
		if( !w[i].nblks )
			continue;

		if( is_write && i != 1 ) {
			DO_IO( di->read_xt, w[i].blk_buf, blk, w[i].nblks );
			memcpy( w[i].blk_buf + w[i].offs, w[i].data, w[i].len );
		}

		n = DO_IO( xt, w[i].blk_buf, blk, w[i].nblks );
		if( n < 0 ) {
			if( !retlen )
				retlen = -1;
			break;
		}
		if( n != w[i].nblks ) {
			w[i].len = MIN( n*di->blksize, w[i].len );
			last = 1;
		}
		if( !is_write && i != 1 )
			memcpy( w[i].data, w[i].blk_buf + w[i].offs, w[i].len );
		retlen += w[i].len;
		blk += n;
	}
	if( retlen > 0 ) {
		mark += retlen;
                di->mark_hi = mark >> BITS;
                di->mark_lo = mark & (ucell) -1;
        }
	return retlen;
}

/* ( addr len -- actual ) */
static void
deblk_read( deblk_info_t *di )
{
	/* printk("deblk_read\n"); */
	int ret = do_readwrite( di, 0, di->read_xt );
	PUSH( ret );
}

/* ( buf len --- actlen ) */
static void
deblk_write( deblk_info_t *di )
{
	int ret = do_readwrite( di, 1, di->write_xt );
	PUSH( ret );
}

/* remember to fix is-deblocker if new methods are added */
NODE_METHODS( deblocker ) = {
	{ "open",	deblk_open 	},
	{ "close",	deblk_close 	},
	{ "read",	deblk_read 	},
	{ "write",	deblk_write 	},
	{ "seek",	deblk_seek 	},
	{ "tell",	deblk_tell 	},
};


void
deblocker_init( void )
{
	REGISTER_NODE( deblocker );
}
