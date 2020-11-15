/*
 *   Creation Date: <2001/05/06 22:47:23 samuel>
 *   Time-stamp: <2004/01/12 10:24:35 samuel>
 *
 *	/packages/hfs-files
 *
 *	HFS world interface
 *
 *   Copyright (C) 2001-2004 Samuel Rydh (samuel@ibrium.se)
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
#include "libc/vsprintf.h"
#include "libc/diskio.h"
#include "libhfs.h"

#define MAC_OS_ROM_CREATOR	0x63687270	/* 'chrp' */
#define MAC_OS_ROM_TYPE		0x74627869	/* 'tbxi' */
#define MAC_OS_ROM_NAME		"Mac OS ROM"

#define FINDER_TYPE		0x464E4452	/* 'FNDR' */
#define FINDER_CREATOR		0x4D414353	/* 'MACS' */
#define SYSTEM_TYPE		0x7A737973	/* 'zsys' */
#define SYSTEM_CREATOR		0x4D414353	/* 'MACS' */

#define VOLNAME_SIZE	64

extern void     hfs_init( void );

typedef struct {
	enum { FILE, DIR } type;
	union {
		hfsdir *dir;
		hfsfile *file;
	};
} hfscommon;

typedef struct {
	hfsvol *vol;
	hfscommon *common;
} hfs_info_t;

DECLARE_NODE( hfs, 0, sizeof(hfs_info_t), "+/packages/hfs-files" );

/************************************************************************/
/*	Search Functions						*/
/************************************************************************/

static int
_find_file( hfsvol *vol, const char *path, unsigned long type, unsigned long creator )
{
	hfsdirent ent;
	hfsdir *dir;
	int ret=1;

	if( !(dir=hfs_opendir(vol, path)) )
		return 1;

	while( ret && !hfs_readdir(dir, &ent) ) {
		if( ent.flags & HFS_ISDIR )
			continue;
		ret = !(*(unsigned long*)ent.u.file.type == type && *(unsigned long*)ent.u.file.creator == creator );
	}

	hfs_closedir( dir );
	return ret;
}


/* ret: 0=success, 1=not_found, 2=not_a_dir */
static int
_search( hfsvol *vol, const char *path, const char *sname, hfsfile **ret_fd )
{
	hfsdir *dir;
	hfsdirent ent;
	int topdir=0, status = 1;
	char *p, buf[256];

	strncpy( buf, path, sizeof(buf) );
	if( buf[strlen(buf)-1] != ':' )
		strncat( buf, ":", sizeof(buf) );
	buf[sizeof(buf)-1] = 0;
	p = buf + strlen( buf );

	if( !(dir=hfs_opendir(vol, path)) )
		return 2;

	/* printk("DIRECTORY: %s\n", path ); */

	while( status && !hfs_readdir(dir, &ent) ) {
		unsigned long type, creator;

		*p = 0;
		topdir = 0;

		strncat( buf, ent.name, sizeof(buf) );
		if( (status=_search(vol, buf, sname, ret_fd)) != 2 )
			continue;
		topdir = 1;

		/* name search? */
		if( sname ) {
			status = strcasecmp( ent.name, sname );
			continue;
		}

		type = *(unsigned long*)ent.u.file.type;
		creator = *(unsigned long*)ent.u.file.creator;

		/* look for Mac OS ROM, System and Finder in the same directory */
		if( type == MAC_OS_ROM_TYPE && creator == MAC_OS_ROM_CREATOR ) {
			if( strcasecmp(ent.name, MAC_OS_ROM_NAME) )
				continue;

			status = _find_file( vol, path, FINDER_TYPE, FINDER_CREATOR )
				|| _find_file( vol, path, SYSTEM_TYPE, SYSTEM_CREATOR );
		}
	}
	if( !status && topdir && ret_fd && !(*ret_fd=hfs_open(vol, buf)) ) {
		printk("Unexpected error: failed to open matched ROM\n");
		status = 1;
	}

	hfs_closedir( dir );
	return status;
}

static hfsfile *
_do_search( hfs_info_t *mi, const char *sname )
{
	hfsvol *vol = hfs_getvol( NULL );

	mi->common->type = FILE;
	(void)_search( vol, ":", sname, &mi->common->file );

	return mi->common->file;
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
print_date(time_t sec)
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
	year += 1970;

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

/*
static void
dir_fs( file_desc_t *fd )
{
	hfscommon *common = (hfscommon*)fd;
	hfsdirent ent;

	if (common->type != DIR)
		return;

	forth_printf("\n");
	while( !hfs_readdir(common->dir, &ent) ) {
		forth_printf("% 10d ", ent.u.file.dsize);
		print_date(ent.mddate);
		if( ent.flags & HFS_ISDIR )
			forth_printf("%s\\\n", ent.name);
		else
			forth_printf("%s\n", ent.name);
	}
}
*/

/************************************************************************/
/*	Standard package methods						*/
/************************************************************************/

/* ( -- success? ) */
static void
hfs_files_open( hfs_info_t *mi )
{
	int fd;
	char *path = my_args_copy();

	const char *s;
	char buf[256];

	fd = open_ih( my_parent() );
	if ( fd == -1 ) {
		free( path );
		RET( 0 );
	}

	mi->vol = hfs_mount(fd, 0);
	if (!mi->vol) {
		RET( 0 );
	}

	if( !strncmp(path, "\\\\", 2) ) {
		hfsvolent ent;

		/* \\ is an alias for the (blessed) system folder */
		if( hfs_vstat(mi->vol, &ent) < 0 || hfs_setcwd(mi->vol, ent.blessed) ) {
			free(path);
			RET( -1 );
		}
		path += 2;
	} else {
		hfs_chdir( mi->vol, ":" );
	}

	mi->common = malloc(sizeof(hfscommon));
	if (!mi->common) {
		free(path);
		RET( 0 );
	}

	if (strcmp(path, "\\") == 0) {
		/* root directory is in fact ":" */
		mi->common->dir = hfs_opendir(mi->vol, ":");
		mi->common->type = DIR;
		free(path);
		RET( -1 );
	}

	if (path[strlen(path) - 1] == '\\') {
		path[strlen(path) - 1] = 0;
	}

	for( path-- ;; ) {
		int n;

		s = ++path;
		path = strchr(s, '\\');
		if( !path || !path[1])
			break;
		n = MIN( sizeof(buf)-1, (path-s) );
		if( !n )
			continue;

		strncpy( buf, s, n );
		buf[n] = 0;
		if( hfs_chdir(mi->vol, buf) ) {
			free(mi->common);
			free(path);
			RET( 0 );
		}
	}

	/* support the ':filetype' syntax */
	if( *s == ':' ) {
		unsigned long id, oldid = hfs_getcwd(mi->vol);
		hfsdirent ent;
		hfsdir *dir;

		s++;
		id = oldid;
		hfs_dirinfo( mi->vol, &id, buf );
		hfs_setcwd( mi->vol, id );

		if( !(dir=hfs_opendir(mi->vol, buf)) ) {
			free(mi->common);
			free(path);
			RET( 0 );
		}
		hfs_setcwd( mi->vol, oldid );

		while( !hfs_readdir(dir, &ent) ) {
			if( ent.flags & HFS_ISDIR )
				continue;
			if( !strncmp(s, ent.u.file.type, 4) ) {
				mi->common->type = FILE;
				mi->common->file = hfs_open( mi->vol, ent.name );
				break;
			}
		}
		hfs_closedir( dir );
		free(path);
		RET( -1 );
	}

	mi->common->dir = hfs_opendir(mi->vol, s);
	if (!mi->common->dir) {
		mi->common->file = hfs_open( mi->vol, s );
		if (mi->common->file == NULL) {
			free(mi->common);
			free(path);
			RET( 0 );
		}
		mi->common->type = FILE;
		free(path);
		RET( -1 );
	}
	mi->common->type = DIR;
	free(path);
	
	RET( -1 );
}

/* ( -- ) */
static void
hfs_files_close( hfs_info_t *mi )
{
	hfscommon *common = mi->common;
	if (common->type == FILE)
		hfs_close( common->file );
	else if (common->type == DIR)
		hfs_closedir( common->dir );
	free(common);
}

/* ( buf len -- actlen ) */
static void
hfs_files_read( hfs_info_t *mi )
{
	int count = POP();
	char *buf = (char *)cell2pointer(POP());

	hfscommon *common = mi->common;
	if (common->type != FILE)
		RET( -1 );

	RET ( hfs_read( common->file, buf, count ) );
}

/* ( pos.d -- status ) */
static void
hfs_files_seek( hfs_info_t *mi )
{
	long long pos = DPOP();
	int offs = (int)pos;
	int whence = SEEK_SET;
	int ret;
	hfscommon *common = mi->common;

	if (common->type != FILE)
		RET( -1 );

	switch( whence ) {
	case SEEK_END:
		whence = HFS_SEEK_END;
		break;
	default:
	case SEEK_SET:
		whence = HFS_SEEK_SET;
		break;
	}

	ret = hfs_seek( common->file, offs, whence );
	if (ret != -1)
		RET( 0 );
	else
		RET( -1 );
}

/* ( addr -- size ) */
static void
hfs_files_load( hfs_info_t *mi )
{
	char *buf = (char *)cell2pointer(POP());
	int count;

	hfscommon *common = mi->common;
	if (common->type != FILE)
		RET( -1 );

	/* Seek to the end in order to get the file size */
	hfs_seek(common->file, 0, HFS_SEEK_END);
	count = common->file->pos;
	hfs_seek(common->file, 0, HFS_SEEK_SET);

	RET ( hfs_read( common->file, buf, count ) );
}

/* ( -- success? ) */
static void
hfs_files_open_nwrom( hfs_info_t *mi )
{
	/* Switch to an existing ROM image file on the fs! */
	if ( _do_search( mi, NULL ) )
		RET( -1 );
	
	RET( 0 );
}

/* ( -- cstr ) */
static void
hfs_files_get_path( hfs_info_t *mi )
{
	char buf[256], buf2[256];
	hfscommon *common = mi->common;
	hfsvol *vol = hfs_getvol( NULL );
	hfsdirent ent;
	int start, ns;
	unsigned long id;

	if (common->type != FILE)
		RET( 0 );

	hfs_fstat( common->file, &ent );
	start = sizeof(buf) - strlen(ent.name) - 1;
	if( start <= 0 )
		RET ( 0 );
	strcpy( buf+start, ent.name );
	buf[--start] = '\\';

	ns = start;
	for( id=ent.parid ; !hfs_dirinfo(vol, &id, buf2) ; ) {
		start = ns;
		ns -= strlen(buf2);
		if( ns <= 0 )
			RET( 0 );
		strcpy( buf+ns, buf2 );
		buf[--ns] = buf[start] = '\\';
	}
	if( strlen(buf) >= sizeof(buf) )
		RET( 0 );

	RET( pointer2cell(strdup(buf+start)) );
}

/* ( -- cstr ) */
static void
hfs_files_get_fstype( hfs_info_t *mi )
{
	PUSH( pointer2cell(strdup("HFS")) );
}

/* ( -- cstr|0 ) */
static void
hfs_files_volume_name( hfs_info_t *mi )
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

/* static method, ( pathstr len ihandle -- ) */
static void
hfs_files_dir( hfs_info_t *dummy )
{
	hfsvol *volume;
	hfscommon *common;
	hfsdirent ent;
	int i;
	int fd;

	ihandle_t ih = POP();
	char *path = pop_fstr_copy();

	fd = open_ih( ih );
	if ( fd == -1 ) {
		free( path );
		return;
	}

	volume = hfs_mount(fd, 0);
	if (!volume) {
		return;
	}

	common = malloc(sizeof(hfscommon));

	/* HFS paths are colon separated, not backslash separated */
	for (i = 0; i < strlen(path); i++)
		if (path[i] == '\\')
			path[i] = ':';

	common->dir = hfs_opendir(volume, path);

	forth_printf("\n");
	while( !hfs_readdir(common->dir, &ent) ) {
                forth_printf("% 10ld ", ent.u.file.dsize);
		print_date(ent.mddate);
		if( ent.flags & HFS_ISDIR )
			forth_printf("%s\\\n", ent.name);
		else
			forth_printf("%s\n", ent.name);
	}

	hfs_closedir( common->dir );
	hfs_umount( volume );

	close_io( fd );

	free( common );
	free( path );
}

/* static method, ( pos.d ih -- flag? ) */
static void
hfs_files_probe( hfs_info_t *dummy )
{
	ihandle_t ih = POP_ih();
	long long offs = DPOP();
	int fd, ret = 0;

	fd = open_ih(ih);
        if (fd >= 0) {
                if (hfs_probe(fd, offs)) {
                        ret = -1;
                }
                close_io(fd);
        } else {
                ret = -1;
        }

	RET (ret);
}

static void
hfs_initializer( hfs_info_t *dummy )
{
	fword("register-fs-package");
}

NODE_METHODS( hfs ) = {
	{ "probe",	hfs_files_probe	},
	{ "open",	hfs_files_open	},
	{ "close",	hfs_files_close },
	{ "read",	hfs_files_read	},
	{ "seek",	hfs_files_seek	},
	{ "load",	hfs_files_load	},
	{ "dir",	hfs_files_dir	},

	/* special */
	{ "open-nwrom",	 	hfs_files_open_nwrom 	},
	{ "get-path",		hfs_files_get_path	},
	{ "get-fstype",		hfs_files_get_fstype	},
	{ "volume-name",	hfs_files_volume_name	},

	{ NULL,		hfs_initializer	},
};

void
hfs_init( void )
{
	REGISTER_NODE( hfs );
}
