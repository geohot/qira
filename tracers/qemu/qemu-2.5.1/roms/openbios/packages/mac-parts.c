/*
 *   Creation Date: <2003/12/04 17:07:05 samuel>
 *   Time-stamp: <2004/01/07 19:36:09 samuel>
 *
 *	<mac-parts.c>
 *
 *	macintosh partition support
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
#include "mac-parts.h"
#include "libc/byteorder.h"
#include "libc/vsprintf.h"
#include "packages.h"

//#define CONFIG_DEBUG_MAC_PARTS

#ifdef CONFIG_DEBUG_MAC_PARTS
#define DPRINTF(fmt, args...) \
do { printk("MAC-PARTS: " fmt , ##args); } while (0)
#else
#define DPRINTF(fmt, args...) do {} while(0)
#endif

typedef struct {
	xt_t		seek_xt, read_xt;
	ucell	        offs_hi, offs_lo;
        ucell	        size_hi, size_lo;
	ucell		bootcode_addr, bootcode_entry;
	unsigned int	blocksize;
	phandle_t	filesystem_ph;
} macparts_info_t;

DECLARE_NODE( macparts, INSTALL_OPEN, sizeof(macparts_info_t), "+/packages/mac-parts" );

#define SEEK( pos )		({ DPUSH(pos); call_parent(di->seek_xt); POP(); })
#define READ( buf, size )	({ PUSH(pointer2cell(buf)); PUSH(size); call_parent(di->read_xt); POP(); })

/* ( open -- flag ) */
static void
macparts_open( macparts_info_t *di )
{
	char *str = my_args_copy();
	char *parstr = NULL, *argstr = NULL;
	char *tmpstr;
	int bs, parnum=-1, apple_parnum=-1;
	int parlist[2], parlist_size = 0;
	desc_map_t dmap;
	part_entry_t par;
	int ret = 0, i = 0, j = 0;
	int want_bootcode = 0;
	phandle_t ph;
	ducell offs = 0, size = -1;

	DPRINTF("macparts_open '%s'\n", str );

	/* 
		Arguments that we accept:
		id: [0-7]
		[(id)][,][filespec]
	*/
	
	if ( str && strlen(str) ) {
		/* Detect the arguments */
		if ((*str >= '0' && *str <= '9') || (*str == ',')) {
		    push_str(str);
		    PUSH(',');
		    fword("left-parse-string");
		    parstr = pop_fstr_copy();
		    argstr = pop_fstr_copy();
		} else {
		    argstr = str;
		}

		/* Make sure argstr is not null */
		if (argstr == NULL)
		    argstr = strdup("");	
		
		/* Convert the id to a partition number */
		if (parstr && strlen(parstr))
		    parnum = atol(parstr);

		/* Detect if we are looking for the bootcode */
		if (strcmp(argstr, "%BOOT") == 0) {
		    want_bootcode = 1;
		}
	}

	DPRINTF("parstr: %s  argstr: %s  parnum: %d\n", parstr, argstr, parnum);

	DPRINTF("want_bootcode %d\n", want_bootcode);
	DPRINTF("macparts_open %d\n", parnum);

	di->filesystem_ph = 0;
	di->read_xt = find_parent_method("read");
	di->seek_xt = find_parent_method("seek");

	SEEK( 0 );
	if( READ(&dmap, sizeof(dmap)) != sizeof(dmap) )
		goto out;

	/* partition maps might support multiple block sizes; in this case,
	 * pmPyPartStart is typically given in terms of 512 byte blocks.
	 */
	bs = __be16_to_cpu(dmap.sbBlockSize);
	if( bs != 512 ) {
		SEEK( 512 );
		READ( &par, sizeof(par) );
		if( __be16_to_cpu(par.pmSig) == DESC_PART_SIGNATURE )
			bs = 512;
	}
	SEEK( bs );
	if( READ(&par, sizeof(par)) != sizeof(par) )
		goto out;
        if (__be16_to_cpu(par.pmSig) != DESC_PART_SIGNATURE)
		goto out;

	/*
	 * Implement partition selection as per the PowerPC Microprocessor CHRP bindings
	 */

	if (argstr == NULL || parnum == 0) {
		/* According to the spec, partition 0 as well as no arguments means the whole disk */
		offs = (long long)0;
		size = (long long)__be32_to_cpu(dmap.sbBlkCount) * bs;

		di->blocksize = (unsigned int)bs;

		di->offs_hi = offs >> BITS;
		di->offs_lo = offs & (ucell) -1;
	
		di->size_hi = size >> BITS;
		di->size_lo = size & (ucell) -1;

		ret = -1;
		goto out;

	} else if (parnum == -1) {

		DPRINTF("mac-parts: counted %d partitions\n", __be32_to_cpu(par.pmMapBlkCnt));

		/* No partition was explicitly requested so let's find a suitable partition... */
		for (i = 1; i <= __be32_to_cpu(par.pmMapBlkCnt); i++) {
			SEEK( bs * i );
			READ( &par, sizeof(par) );
			if ( __be16_to_cpu(par.pmSig) != DESC_PART_SIGNATURE ||
                            !__be32_to_cpu(par.pmPartBlkCnt) )
				continue;

			DPRINTF("found partition %d type: %s with status %x\n", i, par.pmPartType, __be32_to_cpu(par.pmPartStatus));

			/* If we have a valid, allocated and readable partition... */
			if( (__be32_to_cpu(par.pmPartStatus) & kPartitionAUXIsValid) &&
			(__be32_to_cpu(par.pmPartStatus) & kPartitionAUXIsAllocated) &&
			(__be32_to_cpu(par.pmPartStatus) & kPartitionAUXIsReadable) ) {

				/* Unfortunately Apple's OF implementation doesn't follow the OF PowerPC CHRP bindings
				 * and instead will brute-force boot the first valid partition it finds with a
				 * type of either "Apple_Boot", "Apple_HFS" or "DOS_FAT_". Here we store the id
				 * of the first partition that matches these criteria to use as a fallback later
				 * if required. */
				
				if (apple_parnum == -1 &&
				    (strcmp(par.pmPartType, "Apple_Boot") == 0 || 
				    strcmp(par.pmPartType, "Apple_Bootstrap") == 0 || 
				    strcmp(par.pmPartType, "Apple_HFS") == 0 ||
				    strcmp(par.pmPartType, "DOS_FAT_") == 0)) {
					apple_parnum = i;
					
					DPRINTF("Located Apple OF fallback partition %d\n", apple_parnum);
				}
				
				/* If the partition is also bootable and the pmProcessor field matches "PowerPC" (insensitive
				 * match), then according to the CHRP bindings this is our chosen partition */
				for (j = 0; j < strlen(par.pmProcessor); j++) {
				    par.pmProcessor[j] = tolower(par.pmProcessor[j]);
				}				
				
				if ((__be32_to_cpu(par.pmPartStatus) & kPartitionAUXIsBootValid) &&
				    strcmp(par.pmProcessor, "powerpc") == 0) {
				    parnum = i;
				
				    DPRINTF("Located CHRP-compliant boot partition %d\n", parnum);
				}
			}
		}
		
		/* If we found a valid CHRP partition, add it to the list */
		if (parnum > 0) {
		    parlist[parlist_size++] = parnum;
		}

		/* If we found an Apple OF fallback partition, add it to the list */
		if (apple_parnum > 0 && apple_parnum != parnum) {
		    parlist[parlist_size++] = apple_parnum;
		}
		
	} else {
		/* Another partition was explicitly requested */
		parlist[parlist_size++] = parnum;
		
		DPRINTF("Partition %d explicitly requested\n", parnum);
	}

	/* Attempt to use our CHRP partition, optionally followed by our Apple OF fallback partition */
	for (j = 0; j < parlist_size; j++) {
	
	    /* Make sure our partition is valid */
	    parnum = parlist[j];
	    
	    DPRINTF("Selected partition %d\n", parnum);
	    
	    SEEK( bs * parnum );
	    READ( &par, sizeof(par) );	

	    if(! ((__be32_to_cpu(par.pmPartStatus) & kPartitionAUXIsValid) &&
			(__be32_to_cpu(par.pmPartStatus) & kPartitionAUXIsAllocated) &&
			(__be32_to_cpu(par.pmPartStatus) & kPartitionAUXIsReadable)) ) {
		DPRINTF("Partition %d is not valid, allocated and readable\n", parnum);
		goto out;
	    }
	    
	    ret = -1;

	    offs = (long long)__be32_to_cpu(par.pmPyPartStart) * bs;
	    size = (long long)__be32_to_cpu(par.pmPartBlkCnt) * bs;	
	    
	    if (want_bootcode) {
		    
		/* If size == 0 then fail because we requested bootcode but it doesn't exist */
		size = (long long)__be32_to_cpu(par.pmBootSize);
		if (!size) {
		    ret = 0;
		    goto out;
		}

		/* Adjust seek position so 0 = start of bootcode */
		offs += (long long)__be32_to_cpu(par.pmLgBootStart) * bs;

		di->bootcode_addr = __be32_to_cpu(par.pmBootLoad);
		di->bootcode_entry = __be32_to_cpu(par.pmBootEntry);
	    }
	    
	    di->blocksize = (unsigned int)bs;	
	    
	    di->offs_hi = offs >> BITS;
	    di->offs_lo = offs & (ucell) -1;

	    di->size_hi = size >> BITS;
	    di->size_lo = size & (ucell) -1;

	    /* If we're trying to execute bootcode then we're all done */
	    if (want_bootcode) {
	        goto out;
	    }

	    /* We have a valid partition - so probe for a filesystem at the current offset */
	    DPRINTF("mac-parts: about to probe for fs\n");
	    DPUSH( offs );
	    PUSH_ih( my_parent() );
	    parword("find-filesystem");
	    DPRINTF("mac-parts: done fs probe\n");

	    ph = POP_ph();
	    if( ph ) {
		    DPRINTF("mac-parts: filesystem found on partition %d with ph " FMT_ucellx " and args %s\n", parnum, ph, argstr);
		    di->filesystem_ph = ph;
		    
		    /* In case no partition was specified, set a special selected-partition-args property
		       giving the device parameters that we can use to generate bootpath */
		    tmpstr = malloc(strlen(argstr) + 2 + 1);
		    if (strlen(argstr)) {
			sprintf(tmpstr, "%d,%s", parnum, argstr);
		    } else {
			sprintf(tmpstr, "%d", parnum);
		    }

		    push_str(tmpstr);
		    feval("strdup encode-string \" selected-partition-args\" property");

		    free(tmpstr);
		
		    /* If we have been asked to open a particular file, interpose the filesystem package with 
		    the passed filename as an argument */
		    if (strlen(argstr)) {
			    push_str( argstr );
			    PUSH_ph( ph );
			    fword("interpose");
		    }
		    
		    goto out;
	    } else {
		    DPRINTF("mac-parts: no filesystem found on partition %d; bypassing misc-files interpose\n", parnum);
		    
		    /* Here we have a valid partition; however if we tried to pass in a file argument for a
		       partition that doesn't contain a filesystem, then we must fail */
		    if (strlen(argstr)) {
			ret = 0;
		    }
	    }
	}
	    
	free( str );

out:
	PUSH( ret );
}

/* ( block0 -- flag? ) */
static void
macparts_probe( macparts_info_t *dummy )
{
	desc_map_t *dmap = (desc_map_t*)cell2pointer(POP());

	DPRINTF("macparts_probe %x ?= %x\n", dmap->sbSig, DESC_MAP_SIGNATURE);
	if( __be16_to_cpu(dmap->sbSig) != DESC_MAP_SIGNATURE )
		RET(0);
	RET(-1);
}

/* ( -- type offset.d size.d ) */
static void
macparts_get_info( macparts_info_t *di )
{
	DPRINTF("macparts_get_info");

	PUSH( -1 );		/* no type */
	PUSH( di->offs_lo );
	PUSH( di->offs_hi );
	PUSH( di->size_lo );
	PUSH( di->size_hi );
}

/* ( -- size entry addr ) */
static void
macparts_get_bootcode_info( macparts_info_t *di )
{
	DPRINTF("macparts_get_bootcode_info");

	PUSH( di->size_lo );
	PUSH( di->bootcode_entry );
	PUSH( di->bootcode_addr );
}

static void
macparts_block_size( macparts_info_t *di )
{
	DPRINTF("macparts_block_size = %x\n", di->blocksize);
	PUSH(di->blocksize);
}

static void
macparts_initialize( macparts_info_t *di )
{
	fword("register-partition-package");
}

/* ( pos.d -- status ) */
static void
macparts_seek(macparts_info_t *di )
{
	long long pos = DPOP();
	long long offs, size;

	DPRINTF("macparts_seek %llx:\n", pos);

	/* Seek is invalid if we reach the end of the device */
	size = ((ducell)di->size_hi << BITS) | di->size_lo;
	if (pos > size)
		RET( -1 );

	/* Calculate the seek offset for the parent */
	offs = ((ducell)di->offs_hi << BITS) | di->offs_lo;
	offs += pos;
	DPUSH(offs);

	DPRINTF("macparts_seek parent offset %llx:\n", offs);

	call_package(di->seek_xt, my_parent());
}

/* ( buf len -- actlen ) */
static void
macparts_read(macparts_info_t *di )
{
	DPRINTF("macparts_read\n");

	/* Pass the read back up to the parent */
	call_package(di->read_xt, my_parent());
}

/* ( addr -- size ) */
static void
macparts_load( __attribute__((unused))macparts_info_t *di )
{
	/* Invoke the loader */
	load(my_self());
}

/* ( pathstr len -- ) */
static void
macparts_dir( macparts_info_t *di )
{
	/* On PPC Mac, the first partition chosen according to the CHRP boot
	specification (i.e. marked as bootable) may not necessarily contain 
	a valid FS */
	if ( di->filesystem_ph ) {
		PUSH( my_self() );
		push_str("dir");
		PUSH( di->filesystem_ph );
		fword("find-method");
		POP();
		fword("execute");
	} else {
		forth_printf("mac-parts: Unable to determine filesystem\n");
		POP();
		POP();
	}
}

NODE_METHODS( macparts ) = {
	{ "probe",		macparts_probe	 		},
	{ "open",		macparts_open 			},
	{ "seek",		macparts_seek 			},
	{ "read",		macparts_read 			},
	{ "load",		macparts_load 			},
	{ "dir",		macparts_dir 			},
	{ "get-info",		macparts_get_info 		},
	{ "get-bootcode-info",	macparts_get_bootcode_info	},
	{ "block-size",		macparts_block_size 		},
	{ NULL,			macparts_initialize		},
};

void
macparts_init( void )
{
	REGISTER_NODE( macparts );
}
