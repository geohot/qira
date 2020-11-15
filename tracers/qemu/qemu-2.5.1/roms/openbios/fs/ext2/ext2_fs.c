/*
 *	/packages/ext2-files 
 *
 * (c) 2008-2009 Laurent Vivier <Laurent@lvivier.info>
 * (c) 2010 Mark Cave-Ayland <mark.cave-ayland@siriusit.co.uk>
 *
 * This file has been copied from EMILE, http://emile.sf.net
 *
 */

#include "config.h"
#include "libopenbios/bindings.h"
#include "libext2.h"
#include "ext2_utils.h"
#include "fs/fs.h"
#include "libc/vsprintf.h"
#include "libc/diskio.h"

extern void     ext2_init( void );

typedef struct {
	enum { FILE, DIR } type;
	union {
		ext2_FILE *file;
		ext2_DIR *dir;
	};
} ext2_COMMON;

typedef struct {
	ext2_VOLUME *volume;
	ext2_COMMON *common;
} ext2_info_t;

DECLARE_NODE( ext2, 0, sizeof(ext2_info_t), "+/packages/ext2-files" );


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


/************************************************************************/
/*	Standard package methods					*/
/************************************************************************/

/* ( -- success? ) */
static void
ext2_files_open( ext2_info_t *mi )
{
	int fd;
	char *path = my_args_copy();

	fd = open_ih( my_parent() );
	if ( fd == -1 ) {
		free( path );
		RET( 0 );
	}

	mi->volume = ext2_mount(fd);
	if (!mi->volume) {
		RET( 0 );
	}

	mi->common = (ext2_COMMON*)malloc(sizeof(ext2_COMMON));
	if (mi->common == NULL)
		RET( 0 );

	mi->common->dir = ext2_opendir(mi->volume, path);
	if (mi->common->dir == NULL) {
		mi->common->file = ext2_open(mi->volume, path);
		if (mi->common->file == NULL) {
			free(mi->common);
			RET( 0 );
		}
		mi->common->type = FILE;
		RET( -1 );
	}
	mi->common->type = DIR;
	RET( -1 );
}

/* ( -- ) */
static void
ext2_files_close( ext2_info_t *mi )
{
	ext2_COMMON *common = mi->common;

	if (common->type == FILE)
		ext2_close(common->file);
	else if (common->type == DIR)
		ext2_closedir(common->dir);
	free(common);

	ext2_umount(mi->volume);
}

/* ( buf len -- actlen ) */
static void
ext2_files_read( ext2_info_t *mi )
{
	int count = POP();
	char *buf = (char *)cell2pointer(POP());

	ext2_COMMON *common = mi->common;
	if (common->type != FILE)
		RET( -1 );

	RET ( ext2_read( common->file, buf, count ) );
}

/* ( pos.d -- status ) */
static void
ext2_files_seek( ext2_info_t *mi )
{
	long long pos = DPOP();
	int offs = (int)pos;
	int whence = SEEK_SET;
	int ret;
	ext2_COMMON *common = mi->common;

	if (common->type != FILE)
		RET( -1 );

	ret = ext2_lseek(common->file, offs, whence);
	if (ret)
		RET( -1 );
	else
		RET( 0 );
}

/* ( addr -- size ) */
static void
ext2_files_load( ext2_info_t *mi )
{
	char *buf = (char *)cell2pointer(POP());
	int count;

	ext2_COMMON *common = mi->common;
	if (common->type != FILE)
		RET( -1 );

	/* Seek to the end in order to get the file size */
	ext2_lseek(common->file, 0, SEEK_END);
	count = common->file->offset;
	ext2_lseek(common->file, 0, SEEK_SET);

	RET ( ext2_read( common->file, buf, count ) );
}

/* ( -- cstr ) */
static void
ext2_files_get_path( ext2_info_t *mi )
{
	ext2_COMMON *common = mi->common;

	if (common->type != FILE)
		RET( 0 );

	RET( pointer2cell(strdup(common->file->path)) );
}

/* ( -- cstr ) */
static void
ext2_files_get_fstype( ext2_info_t *mi )
{
	PUSH( pointer2cell(strdup("ext2")) );
}

/* static method, ( pathstr len ihandle -- ) */
static void
ext2_files_dir( ext2_info_t *dummy )
{
	ext2_COMMON *common;
	ext2_VOLUME *volume;
	struct ext2_dir_entry_2 *entry;
	struct ext2_inode inode;
	int fd;

	ihandle_t ih = POP();
	char *path = pop_fstr_copy();

	fd = open_ih( ih );
	if ( fd == -1 ) {
		free( path );
		return;
	}

	volume = ext2_mount(fd);
	if (!volume) {
		return;
	}

	common = (ext2_COMMON*)malloc(sizeof(ext2_COMMON));
	common->dir = ext2_opendir(volume, path);

	forth_printf("\n");
	while ( (entry = ext2_readdir(common->dir)) ) {
		ext2_get_inode(common->dir->volume, entry->inode, &inode);
		forth_printf("% 10d ", inode.i_size);
		print_date(inode.i_mtime);
		if (S_ISDIR(inode.i_mode))
			forth_printf("%s\\\n", entry->name);
		else
			forth_printf("%s\n", entry->name);
	}

	ext2_closedir( common->dir );
	ext2_umount( volume );

	close_io( fd );

	free( common );
	free( path );
}

/* static method, ( pos.d ih -- flag? ) */
static void
ext2_files_probe( ext2_info_t *dummy )
{
	ihandle_t ih = POP_ih();
	long long offs = DPOP();
	int fd, ret = 0;

	fd = open_ih(ih);
        if (fd >= 0) {
                if (ext2_probe(fd, offs)) {
                        ret = -1;
                }
                close_io(fd);
        } else {
                ret = -1;
        }

	RET (ret);
}


static void
ext2_initializer( ext2_info_t *dummy )
{
	fword("register-fs-package");
}

NODE_METHODS( ext2 ) = {
	{ "probe",	ext2_files_probe	},
	{ "open",	ext2_files_open		},
	{ "close",	ext2_files_close 	},
	{ "read",	ext2_files_read		},
	{ "seek",	ext2_files_seek		},
	{ "load",	ext2_files_load		},
	{ "dir",	ext2_files_dir		},

	/* special */
	{ "get-path",	ext2_files_get_path	},
	{ "get-fstype",	ext2_files_get_fstype	},

	{ NULL,		ext2_initializer	},
};

void
ext2_init( void )
{
	REGISTER_NODE( ext2 );
}
