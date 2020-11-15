/*
 *   Creation Date: <2001/05/05 23:33:49 samuel>
 *   Time-stamp: <2004/01/12 10:25:39 samuel>
 *
 *	/package/hfsplus-files
 *
 *	HFS+ file system interface (and ROM lookup support)
 *
 *   Copyright (C) 2001, 2002, 2003, 2004 Samuel Rydh (samuel@ibrium.se)
 *   Copyright (C) 2010 Mark Cave-Ayland (mark.cave-ayland@siriusit.co.uk)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation
 *
 */

#include "config.h"
#include "libopenbios/bindings.h"
#include "fs/fs.h"
#include "libhfsp.h"
#include "volume.h"
#include "record.h"
#include "unicode.h"
#include "blockiter.h"
#include "libc/diskio.h"
#include "libc/vsprintf.h"

#define MAC_OS_ROM_CREATOR	0x63687270	/* 'chrp' */
#define MAC_OS_ROM_TYPE		0x74627869	/* 'tbxi' */
#define MAC_OS_ROM_NAME		"Mac OS ROM"

#define FINDER_TYPE		0x464E4452	/* 'FNDR' */
#define FINDER_CREATOR		0x4D414353	/* 'MACS' */
#define SYSTEM_TYPE		0x7A737973	/* 'zsys' */
#define SYSTEM_CREATOR		0x4D414353	/* 'MACS' */

#define VOLNAME_SIZE	64

extern void     hfsp_init( void );

typedef struct {
	record		rec;
	char		*path;
	off_t		pos;
} hfsp_file_t;

typedef struct {
	volume *vol;
	hfsp_file_t *hfspfile;
} hfsp_info_t;

DECLARE_NODE( hfsp, 0, sizeof(hfsp_info_t), "+/packages/hfsplus-files" );


/************************************************************************/
/*	Search implementation						*/
/************************************************************************/

typedef int (*match_proc_t)( record *r, record *parent, const void *match_data, hfsp_file_t *pt );

static int
search_files( record *par, int recursive, match_proc_t proc, const void *match_data, hfsp_file_t *pt )
{
	hfsp_file_t t;
	record r;
	int ret = 1;

	t.path = NULL;

	record_init_parent( &r, par );
	do{
		if( r.record.type == HFSP_FOLDER || r.record.type == HFSP_FILE )
			ret = (*proc)( &r, par, match_data, &t );

		if( ret && r.record.type == HFSP_FOLDER && recursive )
			ret = search_files( &r, 1, proc, match_data, &t );

	} while( ret && !record_next(&r) );

	if( !ret && pt ) {
                char name[256];
                const char *s2 = t.path ? t.path : "";

		unicode_uni2asc( name, &r.key.name, sizeof(name));

		pt->rec = t.rec;
		pt->path = malloc( strlen(name) + strlen(s2) + 2 );
		strcpy( pt->path, name );
		if( strlen(s2) ) {
			strcat( pt->path, "\\" );
			strcat( pt->path, s2 );
		}
	}

	if( t.path )
		free( t.path );

	return ret;
}

static int
root_search_files( volume *vol, int recursive, match_proc_t proc, const void *match_data, hfsp_file_t *pt )
{
	record r;

	record_init_root( &r, &vol->catalog );
	return search_files( &r, recursive, proc, match_data, pt );
}

static int
match_file( record *r, record *parent, const void *match_data, hfsp_file_t *pt )
{
        const char *p = (const char*)match_data;
	char name[256];
	int ret=1;

	if( r->record.type != HFSP_FILE )
		return 1;

	(void) unicode_uni2asc(name, &r->key.name, sizeof(name));
	if( !(ret=strcasecmp(p, name)) && pt )
		pt->rec = *r;

	return ret;
}

static int
match_rom( record *r, record *par, const void *match_data, hfsp_file_t *pt )
{
	hfsp_cat_file *file = &r->record.u.file;
	FInfo *fi = &file->user_info;
	int ret = 1;
	char buf[256];

	if( r->record.type == HFSP_FILE && fi->fdCreator == MAC_OS_ROM_CREATOR && fi->fdType == MAC_OS_ROM_TYPE ) {
		ret = search_files( par, 0, match_file, "System", NULL )
			|| search_files( par, 0, match_file, "Finder", NULL );

		(void) unicode_uni2asc(buf, &r->key.name, sizeof(buf));
		if( !strcasecmp("BootX", buf) )
			return 1;

		if( !ret && pt )
			pt->rec = *r;
	}
	return ret;
}

static int
match_path( record *r, record *par, const void *match_data, hfsp_file_t *pt )
{
	char name[256], *s, *next, *org;
	int ret=1;

 	next = org = strdup( (char*)match_data );
	while( (s=strsep( &next, "\\/" )) && !strlen(s) )
		;
	if( !s ) {
		free( org );
		return 1;
	}

	if( *s == ':' && strlen(s) == 5 ) {
		if( r->record.type == HFSP_FILE && !next ) {
			/* match type */
			hfsp_cat_file *file = &r->record.u.file;
			FInfo *fi = &file->user_info;
			int i, type=0;
			for( i=1; s[i] && i<=4; i++ )
				type = (type << 8) | s[i];
			/* printk("fi->fdType: %s / %s\n", s+1, b ); */
			if( fi->fdType == type ) {
				if( pt )
					pt->rec = *r;
				ret = 0;
			}
		}
	} else {
		(void) unicode_uni2asc(name, &r->key.name, sizeof(name));

		if( !strcasecmp(s, name) ) {
			if( r->record.type == HFSP_FILE && !next ) {
				if( pt )
					pt->rec = *r;
				ret = 0;
			} else /* must be a directory */
				ret = search_files( r, 0, match_path, next, pt );
		}
	}
	free( org );
	return ret;
}


/************************************************************************/
/*	Standard package methods						*/
/************************************************************************/

/* ( -- success? ) */
static void
hfsp_files_open( hfsp_info_t *mi )
{
	int fd;
	char *path = my_args_copy();

	if ( ! path )
		RET( 0 );

	fd = open_ih( my_parent() );
	if ( fd == -1 ) {
		free( path );
		RET( 0 );
	}

	mi->vol = malloc( sizeof(volume) );
	if (volume_open(mi->vol, fd)) {
		free( path );
		close_io( fd );
		RET( 0 );
	}

	mi->hfspfile = malloc( sizeof(hfsp_file_t) );
	
	/* Leading \\ means system folder. The finder info block has
	 * the following meaning.
	 *
	 *  [0] Prefered boot directory ID
	 *  [3] MacOS 9 boot directory ID
	 *  [5] MacOS X boot directory ID
	 */
	if( !strncmp(path, "\\\\", 2) ) {
		int *p = (int*)&(mi->vol)->vol.finder_info[0];
		int cnid = p[0];
		/* printk(" p[0] = %x, p[3] = %x, p[5] = %x\n", p[0], p[3], p[5] ); */
		if( p[0] == p[5] && p[3] )
			cnid = p[3];
		if( record_init_cnid(&(mi->hfspfile->rec), &(mi->vol)->catalog, cnid) )
			RET ( 0 );
		path += 2;
	} else {
		record_init_root( &(mi->hfspfile->rec), &(mi->vol)->catalog );
	}

	if( !search_files(&(mi->hfspfile->rec), 0, match_path, path, mi->hfspfile ) )
		RET ( -1 );
	
	RET ( -1 );
}

/* ( -- ) */
static void
hfsp_files_close( hfsp_info_t *mi )
{
	volume_close(mi->vol);

	if( mi->hfspfile->path )
		free( mi->hfspfile->path );
	free( mi->hfspfile );
}

/* ( buf len -- actlen ) */
static void
hfsp_files_read( hfsp_info_t *mi )
{
	int count = POP();
	char *buf = (char *)cell2pointer(POP());

	hfsp_file_t *t = mi->hfspfile;
	volume *vol = t->rec.tree->vol;
	UInt32 blksize = vol->blksize;
	hfsp_cat_file *file = &t->rec.record.u.file;
	blockiter iter;
	char buf2[blksize];
	int act_count, curpos=0;

	blockiter_init( &iter, vol, &file->data_fork, HFSP_EXTENT_DATA, file->id );
	while( curpos + blksize < t->pos ) {
		if( blockiter_next( &iter ) ) {
			RET ( -1 );
			return;
		}
		curpos += blksize;
	}
	act_count = 0;

	while( act_count < count ){
		UInt32 block = blockiter_curr(&iter);
		int max = blksize, add = 0, size;

		if( volume_readinbuf( vol, buf2, block ) )
			break;

		if( curpos < t->pos ){
			add += t->pos - curpos;
			max -= t->pos - curpos;
		}
		size = (count-act_count > max)? max : count-act_count;
		memcpy( (char *)buf + act_count, &buf2[add], size );

		curpos += blksize;
		act_count += size;

		if( blockiter_next( &iter ) )
			break;
	}

	t->pos += act_count;

	RET ( act_count );
}

/* ( pos.d -- status ) */
static void
hfsp_files_seek( hfsp_info_t *mi )
{
	long long pos = DPOP();
	int offs = (int)pos;
	int whence = SEEK_SET;

	hfsp_file_t *t = mi->hfspfile;
	hfsp_cat_file *file = &t->rec.record.u.file;
	int total = file->data_fork.total_size;

	if( offs == -1 ) {
		offs = 0;
		whence = SEEK_END;
	}

	switch( whence ){
	case SEEK_END:
		t->pos = total + offs;
		break;
	default:
	case SEEK_SET:
		t->pos = offs;
		break;
	}

	if( t->pos < 0 )
		t->pos = 0;

	if( t->pos > total )
		t->pos = total;

	RET ( 0 );
}

/* ( addr -- size ) */
static void
hfsp_files_load( hfsp_info_t *mi )
{
	char *buf = (char *)cell2pointer(POP());

	hfsp_file_t *t = mi->hfspfile;
	volume *vol = t->rec.tree->vol;
	UInt32 blksize = vol->blksize;
	hfsp_cat_file *file = &t->rec.record.u.file;
	int total = file->data_fork.total_size;
	blockiter iter;
	char buf2[blksize];
	int act_count;

	blockiter_init( &iter, vol, &file->data_fork, HFSP_EXTENT_DATA, file->id );

	act_count = 0;

	while( act_count < total ){
		UInt32 block = blockiter_curr(&iter);
		int max = blksize, size;

		if( volume_readinbuf( vol, buf2, block ) )
			break;

		size = (total-act_count > max)? max : total-act_count;
		memcpy( (char *)buf + act_count, &buf2, size );

		act_count += size;

		if( blockiter_next( &iter ) )
			break;
	}

	RET ( act_count );
}

/* ( -- cstr ) */
static void
hfsp_files_get_fstype( hfsp_info_t *mi )
{
	PUSH( pointer2cell(strdup("HFS+")) );
}

/* ( -- cstr ) */
static void
hfsp_files_get_path( hfsp_info_t *mi )
{
	char *buf;
	hfsp_file_t *t = mi->hfspfile;

	if( !t->path )
		RET ( 0 );

	buf = malloc(strlen(t->path) + 1);
	strncpy( buf, t->path, strlen(t->path) );
	buf[strlen(t->path)] = 0;

	PUSH(pointer2cell(buf));
}

/* ( -- success? ) */
static void
hfsp_files_open_nwrom( hfsp_info_t *mi )
{
	/* Switch to an existing ROM image file on the fs! */
	if( !root_search_files(mi->vol, 1, match_rom, NULL, mi->hfspfile) )
		RET ( -1 );

	RET ( 0 );
}

/* ( -- cstr|0 ) */
static void
hfsp_files_volume_name( hfsp_info_t *mi )
{
	int fd;
	char *volname = malloc(VOLNAME_SIZE);

	fd = open_ih(my_self());
        if (fd >= 0) {
                get_hfs_vol_name(fd, volname, VOLNAME_SIZE);
                close_io(fd);
        } else {
                volname[0] = '\0';
        }

	PUSH(pointer2cell(volname));
}

static const int days_month[12] =
	{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
static const int days_month_leap[12] =
	{ 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

static inline int is_leap(int year)
{
	return ((year % 4 == 0) && (year % 100 != 0)) || (year % 400 == 0);
}

static void
print_date(uint32_t sec)
{
	unsigned int second, minute, hour, month, day, year;
	int current;
	const int *days;

	second = sec % 60;
	sec /= 60;

	minute = sec % 60;
	sec /= 60;

	hour = sec % 24;
	sec /= 24;

	year = sec * 100 / 36525;
	sec -= year * 36525 / 100;
	year += 1904;

	days = is_leap(year) ?  days_month_leap : days_month;

	current = 0;
	month = 0;
	while (month < 12) {
		if (sec <= current + days[month]) {
			break;
		}
		current += days[month];
		month++;
	}
	month++;

	day = sec - current + 1;

	forth_printf("%d-%02d-%02d %02d:%02d:%02d ",
		     year, month, day, hour, minute, second);
}

/* static method, ( pathstr len ihandle -- ) */
static void
hfsp_files_dir( hfsp_info_t *dummy )
{
	ihandle_t ih = POP_ih();
	char *path = pop_fstr_copy();
	int fd, found;
	volume *vol;
	record rec, r, folrec;
	char name[256], *curfol, *tmppath;
	
	fd = open_ih(ih);
	if ( fd == -1 ) {
		free( path );
		RET( 0 );
	}

	vol = malloc( sizeof(volume) );
	if (volume_open(vol, fd)) {
		free( path );
		close_io( fd );
		RET( 0 );
	}
	
	/* First move to the specified folder */
	tmppath = strdup(path);
	record_init_root( &rec, &vol->catalog );
	record_init_parent( &r, &rec );
	
	/* Remove initial \ or / */
	curfol = strsep(&tmppath, "\\//");
	curfol = strsep(&tmppath, "\\//");
	forth_printf("\n");
	
	while (curfol && strlen(curfol)) {	    
	    found = 0;
	    do {
		if (r.record.type == HFSP_FOLDER) {
		    unicode_uni2asc(name, &r.key.name, sizeof(name));
		    
		    if (!strcmp(name, curfol)) {
			folrec = r;
			found = -1;
		    }
		}
	    } while ( !record_next(&r) );
	    
	    if (!found) {
		forth_printf("Unable to locate path %s on filesystem\n", path);
		goto done;
	    } else {
		record_init_parent( &r, &folrec );
	    }
	    
	    curfol = strsep(&tmppath, "\\//");
	}
	
	/* Output the directory contents */
	found = 0;
	do {
	    unicode_uni2asc(name, &r.key.name, sizeof(name));
	    
	    if (r.record.type == HFSP_FILE) {
		/* Grab the file entry */
		hfsp_cat_file *file = &r.record.u.file;
		forth_printf("% 10lld ", file->data_fork.total_size);
		print_date(file->create_date);
		forth_printf(" %s\n", name);
		found = -1;
	    }
	    
	    if (r.record.type == HFSP_FOLDER) {
		/* Grab the directory entry */
		hfsp_cat_folder *folder = &r.record.u.folder;
		forth_printf("         0 ");
		print_date(folder->create_date);
		forth_printf(" %s\\\n", name);
		found = -1;
	    }
	    
	} while ( !record_next(&r) );
	
	if (!found) {
	    forth_printf("  (Empty folder)\n");
	}
	
done:
	volume_close(vol);
	free(vol);
	free(path);
	if (tmppath)
	    free(tmppath);
}

/* static method, ( pos.d ih -- flag? ) */
static void
hfsp_files_probe( hfsp_info_t *dummy )
{
	ihandle_t ih = POP_ih();
	long long offs = DPOP();
	int fd, ret = 0;

	fd = open_ih(ih);
        if (fd >= 0) {
                if (volume_probe(fd, offs)) {
                        ret = -1;
                }
                close_io(fd);
        } else {
                ret = -1;
        }

	RET (ret);
}

static void
hfsp_initializer( hfsp_info_t *dummy )
{
	fword("register-fs-package");
}

NODE_METHODS( hfsp ) = {
	{ "probe",	hfsp_files_probe	},
	{ "open",	hfsp_files_open		},
	{ "close",	hfsp_files_close	},
	{ "read",	hfsp_files_read		},
	{ "seek",	hfsp_files_seek		},
	{ "load",	hfsp_files_load		},
	{ "dir",	hfsp_files_dir		},

	/* special */
	{ "open-nwrom",	 	hfsp_files_open_nwrom 	},
	{ "get-path",		hfsp_files_get_path	},
	{ "get-fstype",		hfsp_files_get_fstype	},
	{ "volume-name",	hfsp_files_volume_name	},

	{ NULL,		hfsp_initializer	},
};

void
hfsp_init( void )
{
	REGISTER_NODE( hfsp );
}
