/*
 *   Creation Date: <2003/12/01 00:26:13 samuel>
 *   Time-stamp: <2004/01/07 19:59:53 samuel>
 *
 *	<nvram.c>
 *
 *	medium-level NVRAM handling
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
#include "arch/common/nvram.h"
#include "packages/nvram.h"

//#define CONFIG_DEBUG_NVRAM 1

#ifdef CONFIG_DEBUG_NVRAM
#define DPRINTF(fmt, args...) \
do { printk("NVRAM: " fmt , ##args); } while (0)
#else
#define DPRINTF(fmt, args...) do {} while(0)
#endif

#define DEF_SYSTEM_SIZE	0xc10

#define NV_SIG_SYSTEM	0x70
#define NV_SIG_FREE	0x7f


typedef struct {
	unsigned char	signature;
	unsigned char	checksum;
	unsigned char	len_hi;
	unsigned char	len_lo;
	char		name[12];
	char		data[0];
} nvpart_t;

static struct {
	char		*data;
	int		size;

	nvpart_t	*config;
	int		config_size;
} nvram;


/************************************************************************/
/*	generic								*/
/************************************************************************/

static unsigned int
nvpart_checksum( nvpart_t* hdr )
{
	unsigned char *p = (unsigned char*)hdr;
	int i, val = p[0];

	for( i=2; i<16; i++ ) {
		val += p[i];
		if( val > 255 )
			val = (val - 256 + 1) & 0xff;
	}
	return val;
}

static inline int
nvpart_size( nvpart_t *p )
{
	return (p->len_lo | ((int)p->len_hi<<8)) * 16;
}

static int
next_nvpart( nvpart_t **p )
{
	nvpart_t *end = (nvpart_t*)(nvram.data + nvram.size);
	int len;

	if( !*p ) {
		*p = (nvpart_t*)nvram.data;
		return 1;
	}

	if( !(len=nvpart_size(*p)) ) {
		printk("invalid nvram partition length\n");
		return -1;
	}
	*p = (nvpart_t*)((char*)*p + len);
	if( *p < end )
		return 1;
	if( *p == end )
		return 0;
	return -1;
}

static void
create_free_part( char *ptr, int size )
{
	nvpart_t *nvp = (nvpart_t*)ptr;
	memset( nvp, 0, size );

	strncpy( nvp->name, "777777777777", sizeof(nvp->name) );
	nvp->signature = NV_SIG_FREE;
	nvp->len_hi = (size /16) >> 8;
	nvp->len_lo = size /16;
	nvp->checksum = nvpart_checksum(nvp);
}

static int
create_nv_part( int signature, const char *name, int size )
{
	nvpart_t *p = NULL;
	int fs;

	while( next_nvpart(&p) > 0 ) {
		if( p->signature != NV_SIG_FREE )
			continue;

		fs = nvpart_size( p );
		if( fs < size )
			size = fs;
		p->signature = signature;
		memset( p->name, 0, sizeof(p->name) );
		strncpy( p->name, name, sizeof(p->name) );
		p->len_hi = (size>>8)/16;
		p->len_lo = size/16;
		p->checksum = nvpart_checksum(p);
		if( fs > size ) {
			char *fp = (char*)p + size;
			create_free_part( fp, fs-size );
		}
		return size;
	}
	printk("create-failed\n");
	return -1;
}

static void
zap_nvram( void )
{
	create_free_part( nvram.data, nvram.size );
	create_nv_part( NV_SIG_SYSTEM, "common", DEF_SYSTEM_SIZE );
}

#if 0
static void
show_partitions( void )
{
	nvpart_t *p = NULL;
	char buf[13];

	while( next_nvpart(&p) > 0 ) {
		memcpy( buf, p->name, sizeof(p->name) );
		buf[12] = 0;
		printk("[%02x] %-13s:  %03x\n",
		       p->signature, buf, nvpart_size(p));
	}
}
#endif

void
update_nvram( void )
{
	PUSH( pointer2cell(nvram.config->data) );
	PUSH( nvram.config_size );
	fword("nvram-store-configs");
	arch_nvram_put( nvram.data );
}

void
nvconf_init( void )
{
	int once=0;

	/* initialize nvram structure completely */
	nvram.config = NULL;
	nvram.config_size = 0;

	nvram.size = arch_nvram_size();
	nvram.data = malloc( nvram.size );
	arch_nvram_get( nvram.data );

	bind_func( "update-nvram", update_nvram );

	for( ;; ) {
		nvpart_t *p = NULL;
		int err;

		while( (err=next_nvpart(&p)) > 0 ) {
			if( nvpart_checksum(p) != p->checksum ) {
				err = -1;
				break;
			}
			if( p->signature == NV_SIG_SYSTEM ) {
				nvram.config = p;
				nvram.config_size = nvpart_size(p) - 0x10;

				if( !once++ ) {
					PUSH( pointer2cell(p->data) );
					PUSH( nvram.config_size );
					fword("nvram-load-configs");
				}
			}
		}
		if( err || !nvram.config ) {
			printk("nvram error detected, zapping pram\n");
			zap_nvram();
			if( !once++ )
				fword("set-defaults");
			continue;
		}
		break;
	}
}


/************************************************************************/
/*	nvram								*/
/************************************************************************/

typedef struct {
	unsigned int   mark_hi;
	unsigned int   mark_lo;
} nvram_ibuf_t;

DECLARE_UNNAMED_NODE( nvram, INSTALL_OPEN, sizeof(nvram_ibuf_t ));

/* ( pos_lo pos_hi -- status ) */
static void
nvram_seek( nvram_ibuf_t *nd )
{
	int pos_hi = POP();
	int pos_lo = POP();

	DPRINTF("seek %08x %08x\n", pos_hi, pos_lo );
	nd->mark_lo = pos_lo;
	nd->mark_hi = pos_hi;

	if( nd->mark_lo >= nvram.size ) {
		PUSH(-1);
		return;
	}

	/* 0=success, -1=failure (1=legacy success) */
	PUSH(0);
}

/* ( addr len -- actual ) */
static void
nvram_read( nvram_ibuf_t *nd )
{
	int len = POP();
	char *p = (char*)cell2pointer(POP());
	int n=0;

	while( nd->mark_lo < nvram.size && n < len ) {
		*p++ = nvram.data[nd->mark_lo++];
		n++;
	}
	PUSH(n);
	DPRINTF("read %p %x -- %x\n", p, len, n);
}

/* ( addr len -- actual ) */
static void
nvram_write( nvram_ibuf_t *nd )
{
	int len = POP();
	char *p = (char*)cell2pointer(POP());
	int n=0;

	while( nd->mark_lo < nvram.size && n < len ) {
		nvram.data[nd->mark_lo++] = *p++;
		n++;
	}
	PUSH(n);
	DPRINTF("write %p %x -- %x\n", p, len, n );
}

/* ( -- size ) */
static void
nvram_size( __attribute__((unused)) nvram_ibuf_t *nd )
{
	DPRINTF("nvram_size %d\n", nvram.size);
	PUSH( nvram.size );
}

NODE_METHODS( nvram ) = {
	{ "size",	(void*)nvram_size	},
	{ "read",	(void*)nvram_read	},
	{ "write",	(void*)nvram_write	},
	{ "seek",	(void*)nvram_seek	},
};


void
nvram_init( const char *path )
{
	nvconf_init();

	REGISTER_NAMED_NODE( nvram, path );
}
