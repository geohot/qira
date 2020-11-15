/*
 *	/packages/grubfs-files
 *
 *	grub vfs
 *
 *   Copyright (C) 2004 Stefan Reinauer
 *   Copyright (C) 2004 Samuel Rydh
 *   Copyright (C) 2010 Mark Cave-Ayland
 *
 *   inspired by HFS code from Samuel Rydh
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation
 *
 */

#include "config.h"
#include "libopenbios/bindings.h"
#include "fs/fs.h"
#include "filesys.h"
#include "glue.h"
#include "libc/diskio.h"
#include "libc/vsprintf.h"

extern void     grubfs_init( void );

/************************************************************************/
/* 	grub GLOBALS (horrible... but difficult to fix)			*/
/************************************************************************/

/* the grub drivers want these: */
int		filepos;
int		filemax;
grub_error_t	errnum;
char		FSYS_BUF[FSYS_BUFLEN];

/* these are not even used by us, instead
 * the grub fs drivers want them:
 */
int		fsmax;
void		(*disk_read_hook) (int, int, int);
void		(*disk_read_func) (int, int, int);


/************************************************************************/
/*	filsystem table							*/
/************************************************************************/

typedef struct fsys_entry {
        const char *name;
	int	(*mount_func) (void);
	int	(*read_func) (char *buf, int len);
	int	(*dir_func) (char *dirname);
	void	(*close_func) (void);
	int	(*embed_func) (int *start_sector, int needed_sectors);
} fsys_entry_t;

static const struct fsys_entry fsys_table[] = {
# ifdef CONFIG_FSYS_FAT
    {"fat", fat_mount, fat_read, fat_dir, NULL, NULL},
# endif
# ifdef CONFIG_FSYS_EXT2FS
    {"ext2fs", ext2fs_mount, ext2fs_read, ext2fs_dir, NULL, NULL},
# endif
# ifdef CONFIG_FSYS_MINIX
    {"minix", minix_mount, minix_read, minix_dir, NULL, NULL},
# endif
# ifdef CONFIG_FSYS_REISERFS
    {"reiserfs", reiserfs_mount, reiserfs_read, reiserfs_dir, NULL, reiserfs_embed},
# endif
# ifdef CONFIG_FSYS_JFS
    {"jfs", jfs_mount, jfs_read, jfs_dir, NULL, jfs_embed},
# endif
# ifdef CONFIG_FSYS_XFS
    {"xfs", xfs_mount, xfs_read, xfs_dir, NULL, NULL},
# endif
# ifdef CONFIG_FSYS_UFS
    {"ufs", ufs_mount, ufs_read, ufs_dir, NULL, ufs_embed},
# endif
# ifdef CONFIG_FSYS_ISO9660
    {"iso9660", iso9660_mount, iso9660_read, iso9660_dir, NULL, NULL},
# endif
# ifdef CONFIG_FSYS_NTFS
    {"ntfs", ntfs_mount, ntfs_read, ntfs_dir, NULL, NULL},
# endif
# ifdef CONFIG_FSYS_AFFS
    {"affs", affs_mount, affs_read, affs_dir, NULL, NULL},
# endif
};

/* We don't provide a file search mechanism (yet) */
typedef struct {
	unsigned long	pos;
	unsigned long	len;
	const char	*path;
} grubfile_t;

typedef struct {
	const struct fsys_entry *fsys;
	grubfile_t *fd;
	int dev_fd;
	long long offset;	/* Offset added onto each device read; should only ever be non-zero
				when probing a partition for a filesystem */
} grubfs_t;

typedef struct {
	grubfs_t *gfs;
} grubfs_info_t;

/* Static block and global pointer required for I/O glue */
static grubfs_t dummy_fs;
static grubfs_t *curfs = &dummy_fs;

DECLARE_NODE( grubfs, 0, sizeof(grubfs_info_t), "+/packages/grubfs-files" );


/************************************************************************/
/*	I/O glue (called by grub source)				*/
/************************************************************************/

int
devread( unsigned long sector, unsigned long byte_offset,
	 unsigned long byte_len, void *buf )
{
	long long offs = (long long)sector * 512 + byte_offset;

#ifdef CONFIG_DEBUG_FS
	//printk("devread s=%x buf=%x, fd=%x\n",sector, buf, curfs->dev_fd);
#endif

	if( !curfs ) {
#ifdef CONFIG_DEBUG_FS
		printk("devread: fsys == NULL!\n");
#endif
		return -1;
	}

	if( seek_io(curfs->dev_fd, offs + curfs->offset) ) {
#ifdef CONFIG_DEBUG_FS
		printk("seek failure\n");
#endif
		return -1;
	}
	return (read_io(curfs->dev_fd, buf, byte_len) == byte_len) ? 1:0;
}

int
file_read( void *buf, unsigned long len )
{
	if (filepos < 0 || filepos > filemax)
		filepos = filemax;
	if (len > filemax-filepos)
		len = filemax - filepos;
	errnum = 0;
	return curfs->fsys->read_func( buf, len );
}


/************************************************************************/
/*	Standard package methods					*/
/************************************************************************/

/* ( -- success? ) */
static void
grubfs_files_open( grubfs_info_t *mi )
{
	int fd, i;
	char *path = my_args_copy();
	char *s;

	fd = open_ih( my_parent() );
	if ( fd == -1 ) {
		free( path );
		RET( 0 );
	}

	mi->gfs = &dummy_fs;

	for (i = 0; i < sizeof(fsys_table)/sizeof(fsys_table[0]); i++) {
#ifdef CONFIG_DEBUG_FS
		printk("Trying %s\n", fsys_table[i].name);
#endif
		if (fsys_table[i].mount_func()) {
			const fsys_entry_t *fsys = &fsys_table[i];
#ifdef CONFIG_DEBUG_FS
			printk("Mounted %s\n", fsys->name);
#endif
			mi->gfs = malloc(sizeof(grubfs_t));
			mi->gfs->fsys = fsys;
			mi->gfs->dev_fd = fd;
			mi->gfs->offset = 0;

			s = path;
			while (*s) {
				if(*s=='\\') *s='/';
				s++;
			}
#ifdef CONFIG_DEBUG_FS
			printk("Path=%s\n",path);
#endif
			if (!mi->gfs->fsys->dir_func((char *) path)) {
				forth_printf("File not found\n");
				RET( 0 );
			}

			mi->gfs->fd = malloc(sizeof(grubfile_t));
			mi->gfs->fd->pos = filepos;
			mi->gfs->fd->len = filemax;
			mi->gfs->fd->path = strdup(path);

			RET( -1 );
		}
	}
#ifdef CONFIG_DEBUG_FS
	printk("Unknown filesystem type\n");
#endif

	RET( 0 );
}

/* ( -- ) */
static void
grubfs_files_close( grubfs_info_t *mi )
{
	grubfile_t *gf = mi->gfs->fd;

	if (gf->path)
		free((void *)(gf->path));
	free(gf);

	filepos = 0;
	filemax = 0;
}

/* ( buf len -- actlen ) */
static void
grubfs_files_read( grubfs_info_t *mi )
{
	int count = POP();
	char *buf = (char *)cell2pointer(POP());

	grubfile_t *file = mi->gfs->fd;
        int ret;

	filepos = file->pos;
	filemax = file->len;

	if (count > filemax - filepos)
		count = filemax - filepos;

	ret = mi->gfs->fsys->read_func(buf, count);

	file->pos = filepos;

	RET( ret );
}

/* ( pos.d -- status ) */
static void
grubfs_files_seek( grubfs_info_t *mi )
{
	long long pos = DPOP();
	int offs = (int)pos;
	int whence = SEEK_SET;

	grubfile_t *file = mi->gfs->fd;
	unsigned long newpos;

	switch( whence ) {
	case SEEK_END:
		if (offs < 0 && (unsigned long) -offs > file->len)
			newpos = 0;
		else
			newpos = file->len + offs;
		break;
	default:
	case SEEK_SET:
		newpos = (offs < 0) ? 0 : offs;
		break;
	}

	if (newpos > file->len)
		newpos = file->len;

	file->pos = newpos;

	if (newpos)
		RET( -1 );
	else
		RET( 0 );
}

/* ( addr -- size ) */
static void
grubfs_files_load( grubfs_info_t *mi )
{
	char *buf = (char *)cell2pointer(POP());
	int count, ret;

	grubfile_t *file = mi->gfs->fd;
	count = file->len;

	ret = mi->gfs->fsys->read_func(buf, count);
	file->pos = filepos;

	RET( ret );
}

/* ( -- cstr ) */
static void
grubfs_files_get_path( grubfs_info_t *mi )
{
	grubfile_t *file = mi->gfs->fd;
	const char *path = file->path;

	RET( pointer2cell(strdup(path)) );
}

/* ( -- cstr ) */
static void
grubfs_files_get_fstype( grubfs_info_t *mi )
{
	grubfs_t *gfs = mi->gfs;

	PUSH( pointer2cell(strdup(gfs->fsys->name)) );
}


/* static method, ( pos.d ih -- flag? ) */
static void
grubfs_files_probe( grubfs_info_t *dummy )
{
	ihandle_t ih = POP_ih();
	long long offs = DPOP();
	int i;

	curfs->dev_fd = open_ih(ih);
        if (curfs->dev_fd == -1) {
                RET( -1 );
        }
	curfs->offset = offs;

	for (i = 0; i < sizeof(fsys_table)/sizeof(fsys_table[0]); i++) {
#ifdef CONFIG_DEBUG_FS
		printk("Probing for %s\n", fsys_table[i].name);
#endif
		if (fsys_table[i].mount_func()) {
			RET( -1 );
		}
	}

#ifdef CONFIG_DEBUG_FS
	printk("Unknown filesystem type\n");
#endif

	close_io(curfs->dev_fd);

	RET ( 0 );
}

/* static method, ( pathstr len ihandle -- ) */
static void
grubfs_files_dir( grubfs_info_t *dummy )
{
	forth_printf("dir method not implemented for grubfs filesystem\n");
	POP();
	POP();
	POP();
}

static void
grubfs_initializer( grubfs_info_t *dummy )
{
	fword("register-fs-package");
}

NODE_METHODS( grubfs ) = {
	{ "probe",	grubfs_files_probe	},
	{ "open",	grubfs_files_open	},
	{ "close",	grubfs_files_close 	},
	{ "read",	grubfs_files_read	},
	{ "seek",	grubfs_files_seek	},
	{ "load",	grubfs_files_load	},
	{ "dir",	grubfs_files_dir	},

	/* special */
	{ "get-path",	grubfs_files_get_path	},
	{ "get-fstype",	grubfs_files_get_fstype	},

	{ NULL,		grubfs_initializer	},
};

void
grubfs_init( void )
{
	REGISTER_NODE( grubfs );
}
