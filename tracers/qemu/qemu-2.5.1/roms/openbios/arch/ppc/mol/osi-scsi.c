/*
 *   Creation Date: <2003/12/11 21:23:54 samuel>
 *   Time-stamp: <2004/01/07 19:38:45 samuel>
 *
 *	<osi-scsi.c>
 *
 *	SCSI device node
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
#include "scsi_sh.h"
#include "osi_calls.h"

#define MAX_TARGETS	32

typedef struct {
	int		probed;
	int		valid;		/* a useable device found */

	int		is_cd;
	int		blocksize;
} target_info_t;

static target_info_t 	scsi_devs[ MAX_TARGETS ];

typedef struct {
	int		target;
	target_info_t	*info;
} instance_data_t;


DECLARE_NODE( scsi, INSTALL_OPEN, sizeof(instance_data_t),
	      "/pci/pci-bridge/mol-scsi/sd", "/mol/mol-scsi/sd" );


static int
scsi_cmd_( instance_data_t *sd, const char *cmd, int cmdlen, char *dest,
	   int len, int prelen, int postlen )
{
	char prebuf[4096], postbuf[4096];
	scsi_req_t r[2];	/* the [2] is a hack to get space for the sg-list */
	char sb[32];

	/* memset( dest, 0, len ); */

	if( (unsigned int)prelen > sizeof(prebuf) || (unsigned int)postlen > sizeof(postbuf) ) {
		printk("bad pre/post len %d %d\n", prelen, postlen );
		return 1;
	}

	memset( r, 0, sizeof(r[0]) );
	r->lun = 0;
	r->target = sd->target;
	r->is_write = 0;
	memcpy( r->cdb, cmd, cmdlen );
	r->client_addr = (int)&r;
	r->cdb_len = cmdlen;
	r->sense[0].base = (int)&sb;
	r->sense[0].size = sizeof(sb);
	r->size = prelen + len + postlen;
	r->n_sg = 3;
	r->sglist.n_el = 3;
	r->sglist.vec[0].base = (int)prebuf;
	r->sglist.vec[0].size = prelen;
	r->sglist.vec[1].base = (int)dest;
	r->sglist.vec[1].size = len;
	r->sglist.vec[2].base = (int)postbuf;
	r->sglist.vec[2].size = postlen;

	if( OSI_SCSISubmit((int)&r) ) {
		printk("OSI_SCSISubmit: error!\n");
		return 1;
	}
	while( !OSI_SCSIAck() )
		OSI_USleep( 10 );

	if( r->adapter_status )
		return -1;
	if( r->scsi_status )
		return ((sb[2] & 0xf) << 16) | (sb[12] << 8) | sb[13];
	return 0;
}

static int
scsi_cmd( instance_data_t *sd, const char *cmd, int cmdlen )
{
	return scsi_cmd_( sd, cmd, cmdlen, NULL, 0, 0, 0 );
}

/* ( buf blk nblks -- actual ) */
static void
scsi_read_blocks( instance_data_t *sd )
{
	int nblks = POP();
	int blk = POP();
	char *dest = (char*)POP();
	unsigned char cmd[10];
	int len = nblks * sd->info->blocksize;

	memset( dest, 0, len );

	/* printk("READ: blk: %d length %d\n", blk, len ); */
	memset( cmd, 0, sizeof(cmd) );
	cmd[0] = 0x28; /* READ_10 */
	cmd[2] = blk >> 24;
	cmd[3] = blk >> 16;
	cmd[4] = blk >> 8;
	cmd[5] = blk;
	cmd[7] = nblks >> 8;
	cmd[8] = nblks;

	if( scsi_cmd_(sd, cmd, 10, dest, len, 0, 0) ) {
		printk("read: scsi_cmd failed\n");
		RET( -1 );
	}
	PUSH( nblks );
}

static int
inquiry( instance_data_t *sd )
{
	char inquiry_cmd[6] = { 0x12, 0, 0, 0, 32, 0 };
	char start_stop_unit_cmd[6] = { 0x1b, 0, 0, 0, 1, 0 };
	char test_unit_ready_cmd[6] = { 0x00, 0, 0, 0, 0, 0 };
	char prev_allow_medium_removal[6] = { 0x1e, 0, 0, 0, 1, 0 };
	char set_cd_speed_cmd[12] = { 0xbb, 0, 0xff, 0xff, 0xff, 0xff,
				      0, 0, 0, 0, 0, 0 };
	target_info_t *info = &scsi_devs[sd->target];
	char ret[32];
	int i, sense;

	if( sd->target >= MAX_TARGETS )
		return -1;
	sd->info = info;

	if( info->probed )
		return info->valid ? 0:-1;
	info->probed = 1;

	if( (sense=scsi_cmd_(sd, inquiry_cmd, 6, ret, 2, 0, 0)) ) {
		if( sense < 0 )
			return -1;
		printk("INQUIRY failed\n");
		return -1;
	}

	/* medium present? */
	if( (scsi_cmd(sd, test_unit_ready_cmd, 6) >> 8) == 0x23a ) {
		printk("no media\n");
		return -1;
	}

	info->is_cd = 0;
	info->blocksize = 512;

	if( ret[0] == 5 /* CD/DVD */ ) {
		info->blocksize = 2048;
		info->is_cd = 1;

		scsi_cmd( sd, prev_allow_medium_removal, 6 );
		scsi_cmd( sd, set_cd_speed_cmd, 12 );
		scsi_cmd( sd, start_stop_unit_cmd, 6 );

	} else if( ret[0] == 0 /* DISK */ ) {
		scsi_cmd( sd, test_unit_ready_cmd, 6 );
		scsi_cmd( sd, start_stop_unit_cmd, 6 );
	} else {
		/* don't boot from this device (could be a scanner :-)) */
		return -1;
	}

	/* wait for spin-up (or whatever) to complete */
	for( i=0; ; i++ ) {
		if( i > 300 ) {
			printk("SCSI timeout (sense %x)\n", sense );
			return -1;
		}
		sense = scsi_cmd( sd, test_unit_ready_cmd, 6 );
		if( (sense & 0xf0000) == 0x20000 ) {
			OSI_USleep( 10000 );
			continue;
		}
		break;
	}

	info->valid = 1;
	return 0;
}

/* ( -- success? ) */
static void
scsi_open( instance_data_t *sd )
{
	static int once = 0;
	phandle_t ph;

	fword("my-unit");
	sd->target = POP();

	if( !once ) {
		once++;
		OSI_SCSIControl( SCSI_CTRL_INIT, 0 );
	}

	/* obtiain device information */
	if( inquiry(sd) )
		RET(0);

	selfword("open-deblocker");

	/* interpose disk-label */
	ph = find_dev("/packages/disk-label");
	fword("my-args");
	PUSH_ph( ph );
	fword("interpose");

	PUSH( -1 );
}

/* ( -- ) */
static void
scsi_close( instance_data_t *pb )
{
	selfword("close-deblocker");
}


/* ( -- bs ) */
static void
scsi_block_size( instance_data_t *sd )
{
	PUSH( sd->info->blocksize );
}

/* ( -- maxbytes ) */
static void
scsi_max_transfer( instance_data_t *sd )
{
	PUSH( 1024*1024 );
}

static void
scsi_initialize( instance_data_t *sd )
{
	fword("is-deblocker");
}


NODE_METHODS( scsi ) = {
	{ NULL,			scsi_initialize	},
	{ "open",		scsi_open		},
	{ "close",		scsi_close		},
	{ "read-blocks",	scsi_read_blocks	},
	{ "block-size",		scsi_block_size	},
	{ "max-transfer",	scsi_max_transfer	},
};

void
osiscsi_init( void )
{
	REGISTER_NODE( scsi );
}
