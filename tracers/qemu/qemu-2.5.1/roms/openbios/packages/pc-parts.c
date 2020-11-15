/*
 *   pc partition support
 *
 *   Copyright (C) 2004 Stefan Reinauer
 *
 *   This code is based (and copied in many places) from
 *   mac partition support by Samuel Rydh (samuel@ibrium.se)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   version 2
 *
 */

#include "config.h"
#include "libopenbios/bindings.h"
#include "libopenbios/load.h"
#include "libc/byteorder.h"
#include "libc/vsprintf.h"
#include "packages.h"

//#define DEBUG_PC_PARTS

#ifdef DEBUG_PC_PARTS
#define DPRINTF(fmt, args...)                   \
    do { printk(fmt , ##args); } while (0)
#else
#define DPRINTF(fmt, args...)
#endif

typedef struct {
	xt_t		seek_xt, read_xt;
	ucell	        offs_hi, offs_lo;
        ucell	        size_hi, size_lo;
	phandle_t	filesystem_ph;
} pcparts_info_t;

DECLARE_NODE( pcparts, INSTALL_OPEN, sizeof(pcparts_info_t), "+/packages/pc-parts" );

#define SEEK( pos )		({ DPUSH(pos); call_parent(di->seek_xt); POP(); })
#define READ( buf, size )	({ PUSH(pointer2cell(buf)); PUSH(size); call_parent(di->read_xt); POP(); })

/* three helper functions */

static inline int has_pc_valid_partition(unsigned char *sect)
{
	/* Make sure the partition table contains at least one valid entry */
	return (sect[0x1c2] != 0 || sect[0x1d2] != 0 || sect[0x1e2] != 0);
}

static inline int has_pc_part_magic(unsigned char *sect)
{
	return sect[0x1fe]==0x55 && sect[0x1ff]==0xAA;
}

static inline int is_pc_extended_part(unsigned char type)
{
	return type==5 || type==0xf || type==0x85;
}

/* ( open -- flag ) */
static void
pcparts_open( pcparts_info_t *di )
{
	char *str = my_args_copy();
	char *argstr = strdup("");
	char *parstr = strdup("");
	int bs, parnum=-1;
	int found = 0;
	phandle_t ph;
	ducell offs, size;

	/* Layout of PC partition table */
	struct pc_partition {
		unsigned char boot;
		unsigned char head;
		unsigned char sector;
		unsigned char cyl;
		unsigned char type;
		unsigned char e_head;
		unsigned char e_sector;
		unsigned char e_cyl;
		u32 start_sect; /* unaligned little endian */
		u32 nr_sects; /* ditto */
	} *p, *partition;

	unsigned char buf[512];

	DPRINTF("pcparts_open '%s'\n", str );

	/* 
		Arguments that we accept:
		id: [0-7]
		[(id)][,][filespec]
	*/

	if ( strlen(str) ) {
		/* Detect the arguments */
		if ((*str >= '0' && *str <= '7') || (*str == ',')) {
		    push_str(str);
		    PUSH(',');
		    fword("left-parse-string");
		    parstr = pop_fstr_copy();
		    argstr = pop_fstr_copy();
		} else {
		    argstr = str;
		}
			
		/* Convert the id to a partition number */
		if (parstr && strlen(parstr))
		    parnum = atol(parstr);
	}

	/* Make sure argstr is not null */
	if (argstr == NULL)
	    argstr = strdup("");
	
	DPRINTF("parstr: %s  argstr: %s  parnum: %d\n", parstr, argstr, parnum);
        free(parstr);

	if( parnum < 0 )
		parnum = 0;

	di->filesystem_ph = 0;
	di->read_xt = find_parent_method("read");
	di->seek_xt = find_parent_method("seek");

	SEEK( 0 );
	if( READ(buf, 512) != 512 )
		RET(0);

	/* Check Magic */
	if (!has_pc_part_magic(buf)) {
		DPRINTF("pc partition magic not found.\n");
		RET(0);
	}

	/* Actual partition data */
	partition = (struct pc_partition *) (buf + 0x1be);

	/* Make sure we use a copy accessible from an aligned pointer (some archs
	   e.g. SPARC will crash otherwise) */
	p = malloc(sizeof(struct pc_partition));

	bs = 512;

	if (parnum < 4) {
		/* primary partition */
		partition += parnum;
		memcpy(p, partition, sizeof(struct pc_partition));

		if (p->type == 0 || is_pc_extended_part(p->type)) {
			DPRINTF("partition %d does not exist\n", parnum+1 );
			RET( 0 );
		}

		offs = (long long)(__le32_to_cpu(p->start_sect)) * bs;
		di->offs_hi = offs >> BITS;
		di->offs_lo = offs & (ucell) -1;

		size = (long long)(__le32_to_cpu(p->nr_sects)) * bs;
        	di->size_hi = size >> BITS;
        	di->size_lo = size & (ucell) -1;

		DPRINTF("Primary partition at sector %x\n", __le32_to_cpu(p->start_sect));

		found = 1;
	} else {
		/* Extended partition */
		int i, cur_part;
		unsigned long ext_start, cur_table;

		/* Search for the extended partition
		 * which contains logical partitions */
		for (i = 0; i < 4; i++) {
			if (is_pc_extended_part(p[i].type))
				break;
		}

		if (i >= 4) {
			DPRINTF("Extended partition not found\n");
			RET( 0 );
		}

		DPRINTF("Extended partition at %d\n", i+1);

		/* Visit each logical partition labels */
		ext_start = __le32_to_cpu(p[i].start_sect);
		cur_table = ext_start;
		cur_part = 4;

		while (cur_part <= parnum) {
			DPRINTF("cur_part=%d at %lx\n", cur_part, cur_table);

			SEEK( cur_table * bs );
			if( READ(buf, sizeof(512)) != sizeof(512) )
				RET( 0 );

			if (!has_pc_part_magic(buf)) {
				DPRINTF("Extended partition has no magic\n");
				break;
			}

			/* Read the extended partition, making sure we are aligned again */
			partition = (struct pc_partition *) (buf + 0x1be);
			memcpy(p, partition, sizeof(struct pc_partition));

			/* First entry is the logical partition */
			if (cur_part == parnum) {
				if (p->type == 0) {
					DPRINTF("Partition %d is empty\n", parnum+1);
					RET( 0 );
				}

				offs = (long long)(cur_table+__le32_to_cpu(p->start_sect)) * bs;
				di->offs_hi = offs >> BITS;
				di->offs_lo = offs & (ucell) -1;

				size = (long long)__le32_to_cpu(p->nr_sects) * bs;
				di->size_hi = size >> BITS;
				di->size_lo = size & (ucell) -1;

				found = 1;
				break;
			}

			/* Second entry is link to next partition */
			if (!is_pc_extended_part(p[1].type)) {
				DPRINTF("no link\n");
				break;
			}

			cur_table = ext_start + __le32_to_cpu(p[1].start_sect);
			cur_part++;
		}

		if (!found) {
			DPRINTF("Logical partition %d does not exist\n", parnum+1);
			RET( 0 );
		}
	}
	
	free(p);

	if (found) {
		/* We have a valid partition - so probe for a filesystem at the current offset */
		DPRINTF("pc-parts: about to probe for fs\n");
		DPUSH( offs );
		PUSH_ih( my_parent() );
		parword("find-filesystem");
		DPRINTF("pc-parts: done fs probe\n");
	
		ph = POP_ph();
		if( ph ) {
			DPRINTF("pc-parts: filesystem found with ph " FMT_ucellx " and args %s\n", ph, argstr);
			di->filesystem_ph = ph;

			/* If we have been asked to open a particular file, interpose the filesystem package with 
			the passed filename as an argument */
			if (strlen(argstr)) {
				push_str( argstr );
				PUSH_ph( ph );
				fword("interpose");
			}
		} else {
			DPRINTF("pc-parts: no filesystem found; bypassing misc-files interpose\n");
		}
	
		free( str );
		RET( -1 );
	} else {
		DPRINTF("pc-parts: unable to locate partition\n");

		free( str );
		RET( 0 );
	}
}

/* ( block0 -- flag? ) */
static void
pcparts_probe( pcparts_info_t *dummy )
{
	unsigned char *buf = (unsigned char *)cell2pointer(POP());

	DPRINTF("probing for PC partitions\n");

	/* We also check that at least one valid partition exists; this is because
	some CDs seem broken in that they have a partition table but it is empty
	e.g. MorphOS. */
	RET ( has_pc_part_magic(buf) && has_pc_valid_partition(buf) );
}

/* ( -- type offset.d size.d ) */
static void
pcparts_get_info( pcparts_info_t *di )
{
	DPRINTF("PC get_info\n");
	PUSH( -1 );		/* no type */
	PUSH( di->offs_lo );
	PUSH( di->offs_hi );
	PUSH( di->size_lo );
	PUSH( di->size_hi );
}

static void
pcparts_block_size( __attribute__((unused))pcparts_info_t *di )
{
	PUSH(512);
}

static void
pcparts_initialize( pcparts_info_t *di )
{
	fword("register-partition-package");
}

/* ( pos.d -- status ) */
static void
pcparts_seek(pcparts_info_t *di )
{
	long long pos = DPOP();
	long long offs, size;

	DPRINTF("pcparts_seek %llx:\n", pos);

	/* Seek is invalid if we reach the end of the device */
	size = ((ducell)di->size_hi << BITS) | di->size_lo;
	if (pos > size)
		RET( -1 );

	/* Calculate the seek offset for the parent */
	offs = ((ducell)di->offs_hi << BITS) | di->offs_lo;
	offs += pos;
	DPUSH(offs);

	DPRINTF("pcparts_seek parent offset %llx:\n", offs);

	call_package(di->seek_xt, my_parent());
}

/* ( buf len -- actlen ) */
static void
pcparts_read(pcparts_info_t *di )
{
	DPRINTF("pcparts_read\n");

	/* Pass the read back up to the parent */
	call_package(di->read_xt, my_parent());
}

/* ( addr -- size ) */
static void
pcparts_load( __attribute__((unused))pcparts_info_t *di )
{
	/* Invoke the loader */
	load(my_self());
}

/* ( pathstr len -- ) */
static void
pcparts_dir( pcparts_info_t *di )
{
	if ( di->filesystem_ph ) {
		PUSH( my_self() );
		push_str("dir");
		PUSH( di->filesystem_ph );
		fword("find-method");
		POP();
		fword("execute");
	} else {
		forth_printf("pc-parts: Unable to determine filesystem\n");
		POP();
		POP();
	}
}

NODE_METHODS( pcparts ) = {
	{ "probe",	pcparts_probe 		},
	{ "open",	pcparts_open 		},
	{ "seek",	pcparts_seek 		},
	{ "read",	pcparts_read 		},
	{ "load",	pcparts_load 		},
	{ "dir",	pcparts_dir 		},
	{ "get-info",	pcparts_get_info 	},
	{ "block-size",	pcparts_block_size 	},
	{ NULL,		pcparts_initialize	},
};

void
pcparts_init( void )
{
	REGISTER_NODE( pcparts );
}
