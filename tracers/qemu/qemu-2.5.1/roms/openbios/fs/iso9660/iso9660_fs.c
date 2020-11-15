/*
 * /packages/iso9660-files filesystem handler
 *
 * (c) 2009 Laurent Vivier <Laurent@vivier.eu>
 * (c) 2010 Mark Cave-Ayland <mark.cave-ayland@siriusit.co.uk>
 */

#include "config.h"
#include "libopenbios/bindings.h"
#include "libiso9660.h"
#include "fs/fs.h"
#include "libc/vsprintf.h"
#include "libc/diskio.h"

extern void     iso9660_init( void );

typedef struct {
	enum { FILE, DIR } type;
	union {
		iso9660_FILE *file;
		iso9660_DIR * dir;
	};
} iso9660_COMMON;

typedef struct {
	iso9660_VOLUME *volume;
	iso9660_COMMON *common;
} iso9660_info_t;

DECLARE_NODE( iso9660, 0, sizeof(iso9660_info_t), "+/packages/iso9660-files" );

/* ( -- success? ) */
static void
iso9660_files_open( iso9660_info_t *mi )
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
 
	mi->volume = iso9660_mount( fd );
	if ( mi->volume == NULL ) {
		free( path );
		close_io( fd );
		RET( 0 );
	}

	mi->common->dir = iso9660_opendir( mi->volume, path );
	if ( mi->common->dir == NULL ) {
		mi->common->file = iso9660_open( mi->volume, path );
		if (mi->common->file == NULL) {
			iso9660_umount( mi->volume );
			close_io( fd );
			free( path );
			RET( 0 );
		}
		mi->common->type = FILE;
		free( path );
		RET( -1 );
 	}
	mi->common->type = DIR;
	free( path );

	RET( -1 );
}

/* ( -- ) */
static void
iso9660_files_close( iso9660_info_t *mi )
{
	int fd = mi->volume->fd;
 
	if (mi->common->type == FILE )
		iso9660_close( mi->common->file );
	else if ( mi->common->type == DIR )
		iso9660_closedir( mi->common->dir );
	iso9660_umount( mi->volume );
	close_io( fd );
}

/* ( buf len -- actlen ) */
static void
iso9660_files_read( iso9660_info_t *mi )
{
	int count = POP();
	char *buf = (char *)cell2pointer(POP());
	int ret;
 
	if ( mi->common->type != FILE )
		PUSH( 0 );
 
	ret = iso9660_read( mi->common->file, buf, count );
 
	PUSH( ret );
}

/* ( pos.d -- status ) */
static void
iso9660_files_seek( iso9660_info_t *mi )
{
	long long pos = DPOP();
	cell ret;
	int offs = (int)pos;
	int whence = SEEK_SET;

	if (mi->common->type != FILE)
		PUSH( -1 );

	if( offs == -1 ) {
		offs = 0;
		whence = SEEK_END;
	}
 
	ret = iso9660_lseek(mi->common->file, offs, whence);
 
	PUSH( (ret < 0)? -1 : 0 );
}

/* ( -- filepos.d ) */
static void
iso9660_files_offset( iso9660_info_t *mi )
{
	if ( mi->common->type != FILE )
		DPUSH( -1 );
 
	DPUSH( mi->common->file->offset );
}

/* ( addr -- size ) */
static void
iso9660_files_load( iso9660_info_t *mi)
{
	char *buf = (char*)cell2pointer(POP());
	int ret, size;
 
	if ( mi->common->type != FILE )
		PUSH( 0 );
 
	size = 0;
	while(1) {
		ret = iso9660_read( mi->common->file, buf, 512 );
		if (ret <= 0)
			break;
		buf += ret;
		size += ret;
		if (ret != 512)
			break;
	}
	PUSH( size );
}

/* static method, ( pathstr len ihandle -- ) */
static void
iso9660_files_dir( iso9660_info_t *dummy )
{
	iso9660_VOLUME *volume;
	iso9660_COMMON *common;
	struct iso_directory_record *idr;
	char name_buf[256];
	int fd;
 
	ihandle_t ih = POP();
	char *path = pop_fstr_copy();

	fd = open_ih( ih );
	if ( fd == -1 ) {
		free( path );
		return;
	}
 
	volume = iso9660_mount( fd );
	if ( volume == NULL ) {
		free ( path );
		close_io( fd );
		return;
	}

	common = malloc(sizeof(iso9660_COMMON));
	common->dir = iso9660_opendir( volume, path );

	forth_printf("\n");
	while ( (idr = iso9660_readdir(common->dir)) ) {
 
		forth_printf("% 10d ", isonum_733(idr->size));
		forth_printf("%d-%02d-%02d %02d:%02d:%02d ",
			     idr->date[0] + 1900, /* year */
			     idr->date[1], /* month */
                             idr->date[2], /* day */
			     idr->date[3], idr->date[4], idr->date[5]);
		iso9660_name(common->dir->volume, idr, name_buf);
		if (idr->flags[0] & 2)
			forth_printf("%s\\\n", name_buf);
		else
			forth_printf("%s\n", name_buf);
	}

	iso9660_closedir( common->dir );
	iso9660_umount( volume );

	close_io( fd );

	free( common );
	free( path );
}

/* static method, ( pos.d ih -- flag? ) */
static void
iso9660_files_probe( iso9660_info_t *dummy )
{
	ihandle_t ih = POP_ih();
	long long offs = DPOP();
	int fd, ret = 0;

	fd = open_ih(ih);
        if (fd >= 0) {
                if (iso9660_probe(fd, offs)) {
                        ret = -1;
                }
                close_io(fd);
        } else {
                ret = -1;
        }

	RET (ret);
}

static void
iso9660_files_block_size( iso9660_info_t *dummy )
{
	PUSH(2048);
}
 
static void
iso9660_initializer( iso9660_info_t *dummy )
{
	fword("register-fs-package");
}
 
NODE_METHODS( iso9660 ) = {
	{ "probe",	iso9660_files_probe		},
	{ "open",	iso9660_files_open		},
	{ "close",	iso9660_files_close		},
	{ "read",	iso9660_files_read		},
	{ "seek",	iso9660_files_seek		},
	{ "offset",	iso9660_files_offset		},
	{ "load",	iso9660_files_load		},
	{ "dir",	iso9660_files_dir		},
	{ "block-size",	iso9660_files_block_size	},
	{ NULL,		iso9660_initializer	},
};

void
iso9660_init( void )
{
	REGISTER_NODE( iso9660 );
}
