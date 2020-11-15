/*
 *   Creation Date: <2003/12/03 22:10:45 samuel>
 *   Time-stamp: <2004/01/07 19:17:45 samuel>
 *
 *	<disk-label.c>
 *
 *	Partition support
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
#include "libopenbios/load.h"
#include "libc/diskio.h"
#include "libc/vsprintf.h"
#include "packages.h"

//#define DEBUG_DISK_LABEL

#ifdef DEBUG_DISK_LABEL
#define DPRINTF(fmt, args...) \
do { printk("DISK-LABEL - %s: " fmt, __func__ , ##args); } while (0)
#else
#define DPRINTF(fmt, args...) do { } while (0)
#endif

typedef struct {
	xt_t 		parent_seek_xt;
	xt_t 		parent_tell_xt;
	xt_t		parent_read_xt;

        ucell	        offs_hi, offs_lo;
        ucell	        size_hi, size_lo;
	int		block_size;
	int		type;		/* partition type or -1 */

	ihandle_t	part_ih;
	phandle_t	filesystem_ph;
} dlabel_info_t;

DECLARE_NODE( dlabel, 0, sizeof(dlabel_info_t), "/packages/disk-label" );


/* ( -- ) */
static void
dlabel_close( __attribute__((unused))dlabel_info_t *di )
{
}

/* ( -- success? ) */
static void
dlabel_open( dlabel_info_t *di )
{
	char *path;
	char block0[512];
	phandle_t ph;
	int success=0;
	cell status;

	path = my_args_copy();

	DPRINTF("dlabel-open '%s'\n", path );

	di->part_ih = 0;

	/* Find parent methods */
	di->filesystem_ph = 0;
	di->parent_seek_xt = find_parent_method("seek");
	di->parent_tell_xt = find_parent_method("tell");
	di->parent_read_xt = find_parent_method("read");

	/* If arguments have been passed, determine the partition/filesystem type */
	if (path && strlen(path)) {

		/* Read first block from parent device */
		DPUSH(0);
		call_package(di->parent_seek_xt, my_parent());
		POP();

		PUSH(pointer2cell(block0));
		PUSH(sizeof(block0));
		call_package(di->parent_read_xt, my_parent());
		status = POP();
		if (status != sizeof(block0))
			goto out;

		/* Find partition handler */
		PUSH( pointer2cell(block0) );
		selfword("find-part-handler");
		ph = POP_ph();
		if( ph ) {
			/* We found a suitable partition handler, so interpose it */
			DPRINTF("Partition found on disk - scheduling interpose with ph " FMT_ucellx "\n", ph);

			push_str(path);
			PUSH_ph(ph);
			fword("interpose");	

			success = 1;
		} else {
			/* unknown (or missing) partition map,
			* try the whole disk
			*/

			DPRINTF("Unknown or missing partition map; trying whole disk\n");

			/* Probe for filesystem from start of device */
			DPUSH ( 0 );	
			PUSH_ih( my_self() );
			selfword("find-filesystem");
			ph = POP_ph();
			if( ph ) {
				/* If we have been asked to open a particular file, interpose the filesystem package with the passed filename as an argument */
				di->filesystem_ph = ph;

				DPRINTF("Located filesystem with ph " FMT_ucellx "\n", ph);
				DPRINTF("path: %s length: %d\n", path, strlen(path));

				if (path && strlen(path)) {
					DPRINTF("INTERPOSE!\n");

					push_str( path );
					PUSH_ph( ph );
					fword("interpose");
				}
			} else if (path && strcmp(path, "%BOOT") != 0) {
				goto out;
			}

			success = 1;
		}
	} else {
		/* No arguments were passed, so we just use the parent raw device directly */
		success = 1;
	}

out:
	if( path )
		free( path );
	if( !success ) {
		dlabel_close( di );
		RET(0);
	}
	PUSH(-1);
}

/* ( addr len -- actual ) */
static void
dlabel_read( dlabel_info_t *di )
{
	/* Call back up to parent */
	call_package(di->parent_read_xt, my_parent());
}

/* ( pos.d -- status ) */
static void
dlabel_seek( dlabel_info_t *di )
{
	/* Call back up to parent */
	call_package(di->parent_seek_xt, my_parent());
}

/* ( -- filepos.d ) */
static void
dlabel_tell( dlabel_info_t *di )
{
	/* Call back up to parent */
	call_package(di->parent_tell_xt, my_parent());
}

/* ( addr len -- actual ) */
static void
dlabel_write( __attribute__((unused)) dlabel_info_t *di )
{
	DDROP();
	PUSH( -1 );
}

/* ( addr -- size ) */
static void
dlabel_load( __attribute__((unused)) dlabel_info_t *di )
{
	/* Try the load method of the part package */
	xt_t xt;

	/* If we have a partition handle, invoke the load word on it */
	if (di->part_ih) {
		xt = find_ih_method("load", di->part_ih);
		if (!xt) {
			forth_printf("load currently not implemented for ihandle " FMT_ucellx "\n", di->part_ih);
			PUSH(0);
			return;
		}
	
		DPRINTF("calling load on ihandle " FMT_ucellx "\n", di->part_ih);

		call_package(xt, di->part_ih);
	} else {
		/* Otherwise attempt load directly on the raw disk */
		DPRINTF("calling load on raw disk ihandle " FMT_ucellx "\n", my_self());

		load(my_self());
	}
}

/* ( pathstr len -- ) */
static void
dlabel_dir( dlabel_info_t *di )
{
	if ( di->filesystem_ph ) {
		PUSH( my_self() );
		push_str("dir");
		PUSH( di->filesystem_ph );
		fword("find-method");
		POP();
		fword("execute");
 	} else {
		forth_printf("disk-label: Unable to determine filesystem\n");
		POP();
		POP();
	}
}

NODE_METHODS( dlabel ) = {
	{ "open",	dlabel_open 	},
	{ "close",	dlabel_close 	},
	{ "load",	dlabel_load 	},
	{ "read",	dlabel_read 	},
	{ "write",	dlabel_write 	},
	{ "seek",	dlabel_seek 	},
	{ "tell",	dlabel_tell 	},
	{ "dir",	dlabel_dir 	},
};

void
disklabel_init( void )
{
	REGISTER_NODE( dlabel );
}
