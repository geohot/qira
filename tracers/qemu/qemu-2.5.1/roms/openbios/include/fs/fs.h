/*
 *   Creation Date: <2001/05/06 17:12:45 samuel>
 *   Time-stamp: <2003/10/22 11:43:45 samuel>
 *
 *	<fs_loader.h>
 *
 *	Generic file system access
 *
 *   Copyright (C) 2001, 2002, 2003 Samuel Rydh (samuel@ibrium.se)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation
 *
 */

#ifndef _H_FS
#define _H_FS


typedef struct fs_ops 		fs_ops_t;
typedef struct opaque_struct	file_desc_t;

#define fs_open_path( fs, path ) 	(fs)->open_path( fs, path )
#define fs_search_rom( fs )		(fs)->search_rom( fs )
#define fs_search_file( fs, name )	(fs)->search_file( fs, name )
#define fs_vol_name( fs, buf, size )	(fs)->vol_name( fs, buf, size )

struct fs_ops {
	void		*fs_data;
	int		fd;		/* owner block device */
	int		type;

	void		(*close_fs)( fs_ops_t *fs );
	file_desc_t 	*(*open_path)( fs_ops_t *fs, const char *path );
	file_desc_t 	*(*search_rom)( fs_ops_t *fs );
	file_desc_t 	*(*search_file)( fs_ops_t *fs, const char *name );
	char		*(*vol_name)( fs_ops_t *fs, char *buf, int size );

	/* file ops */
	void		(*close)( file_desc_t *file );
	int		(*read)( file_desc_t *file, void *buf, size_t count );
	int		(*lseek)( file_desc_t *file, off_t offset, int whence );
	char		*(*get_path)( file_desc_t *file, char *buf, int len );
	void		(*dir)( file_desc_t *file );

        const char     	*(*get_fstype)( fs_ops_t *fs );
};

extern fs_ops_t		*fs_open( int fs_type, int fd );
extern void		fs_close( fs_ops_t *fs );
const char 		*fs_get_name( fs_ops_t *fs );

#ifdef CONFIG_HFSP
extern int		fs_hfsp_open( int fd, fs_ops_t *fs );
extern int 		fs_hfsp_probe( int fd, long long offs );
#else
static inline int	fs_hfsp_open( int fd, fs_ops_t *fs ) { return -1; }
static inline int	fs_hfsp_probe( int fd, long long offs ) { return -1; }
#endif

#ifdef CONFIG_HFS
extern int		fs_hfs_open( int fd, fs_ops_t *fs );
extern int 		fs_hfs_probe( int fd, long long offs );
#else
static inline int	fs_hfs_open( int fd, fs_ops_t *fs ) { return -1; }
static inline int	fs_hfs_probe( int fd, long long offs ) { return -1; }
#endif

#ifdef CONFIG_ISO9660
extern int		fs_iso9660_open( int fd, fs_ops_t *fs );
extern int 		fs_iso9660_probe( int fd, long long offs );
#else
static inline int	fs_iso9660_open( int fd, fs_ops_t *fs ) { return -1; }
static inline int	fs_iso9660_probe( int fd, long long offs ) { return -1; }
#endif

#ifdef CONFIG_EXT2
extern int		fs_ext2_open( int fd, fs_ops_t *fs );
extern int 		fs_ext2_probe( int fd, long long offs );
#else
static inline int	fs_ext2_open( int fd, fs_ops_t *fs ) { return -1; }
static inline int	fs_ext2_probe( int fd, long long offs ) { return -1; }
#endif

#ifdef CONFIG_GRUBFS
extern int		fs_grubfs_open( int fd, fs_ops_t *fs );
extern int 		fs_grubfs_probe( int fd, long long offs );
#else
static inline int	fs_grubfs_open( int fd, fs_ops_t *fs ) { return -1; }
static inline int	fs_grubfs_probe( int fd, long long offs ) { return -1; }
#endif



/* misc */
extern char 		*get_hfs_vol_name( int fd, char *buf, int size );


#endif   /* _H_FS */
