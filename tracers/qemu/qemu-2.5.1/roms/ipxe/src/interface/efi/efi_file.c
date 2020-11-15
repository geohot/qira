/*
 * Copyright (C) 2013 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * You can also choose to distribute this program under the terms of
 * the Unmodified Binary Distribution Licence (as given in the file
 * COPYING.UBDL), provided that you have satisfied its requirements.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/**
 * @file
 *
 * EFI file protocols
 *
 */

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <wchar.h>
#include <ipxe/image.h>
#include <ipxe/efi/efi.h>
#include <ipxe/efi/Protocol/SimpleFileSystem.h>
#include <ipxe/efi/Protocol/BlockIo.h>
#include <ipxe/efi/Protocol/DiskIo.h>
#include <ipxe/efi/Guid/FileInfo.h>
#include <ipxe/efi/Guid/FileSystemInfo.h>
#include <ipxe/efi/efi_strings.h>
#include <ipxe/efi/efi_file.h>

/** EFI file information GUID */
static EFI_GUID efi_file_info_id = EFI_FILE_INFO_ID;

/** EFI file system information GUID */
static EFI_GUID efi_file_system_info_id = EFI_FILE_SYSTEM_INFO_ID;

/** EFI media ID */
#define EFI_MEDIA_ID_MAGIC 0x69505845

/** An image exposed as an EFI file */
struct efi_file {
	/** EFI file protocol */
	EFI_FILE_PROTOCOL file;
	/** Image */
	struct image *image;
	/** Current file position */
	size_t pos;
};

static struct efi_file efi_file_root;

/**
 * Get EFI file name (for debugging)
 *
 * @v file		EFI file
 * @ret name		Name
 */
static const char * efi_file_name ( struct efi_file *file ) {

	return ( file->image ? file->image->name : "<root>" );
}

/**
 * Find EFI file image
 *
 * @v wname		Filename
 * @ret image		Image, or NULL
 */
static struct image * efi_file_find ( const CHAR16 *wname ) {
	char name[ wcslen ( wname ) + 1 /* NUL */ ];
	struct image *image;

	/* Find image */
	snprintf ( name, sizeof ( name ), "%ls", wname );
	list_for_each_entry ( image, &images, list ) {
		if ( strcasecmp ( image->name, name ) == 0 )
			return image;
	}

	return NULL;

}

/**
 * Open file
 *
 * @v this		EFI file
 * @ret new		New EFI file
 * @v wname		Filename
 * @v mode		File mode
 * @v attributes	File attributes (for newly-created files)
 * @ret efirc		EFI status code
 */
static EFI_STATUS EFIAPI
efi_file_open ( EFI_FILE_PROTOCOL *this, EFI_FILE_PROTOCOL **new,
		CHAR16 *wname, UINT64 mode __unused,
		UINT64 attributes __unused ) {
	struct efi_file *file = container_of ( this, struct efi_file, file );
	struct efi_file *new_file;
	struct image *image;

	/* Initial '\' indicates opening from the root directory */
	while ( *wname == L'\\' ) {
		file = &efi_file_root;
		wname++;
	}

	/* Allow root directory itself to be opened */
	if ( ( wname[0] == L'\0' ) || ( wname[0] == L'.' ) ) {
		*new = &efi_file_root.file;
		return 0;
	}

	/* Fail unless opening from the root */
	if ( file->image ) {
		DBGC ( file, "EFIFILE %s is not a directory\n",
		       efi_file_name ( file ) );
		return EFI_NOT_FOUND;
	}

	/* Identify image */
	image = efi_file_find ( wname );
	if ( ! image ) {
		DBGC ( file, "EFIFILE \"%ls\" does not exist\n", wname );
		return EFI_NOT_FOUND;
	}

	/* Fail unless opening read-only */
	if ( mode != EFI_FILE_MODE_READ ) {
		DBGC ( file, "EFIFILE %s cannot be opened in mode %#08llx\n",
		       image->name, mode );
		return EFI_WRITE_PROTECTED;
	}

	/* Allocate and initialise file */
	new_file = zalloc ( sizeof ( *new_file ) );
	memcpy ( &new_file->file, &efi_file_root.file,
		 sizeof ( new_file->file ) );
	new_file->image = image_get ( image );
	*new = &new_file->file;
	DBGC ( new_file, "EFIFILE %s opened\n", efi_file_name ( new_file ) );

	return 0;
}

/**
 * Close file
 *
 * @v this		EFI file
 * @ret efirc		EFI status code
 */
static EFI_STATUS EFIAPI efi_file_close ( EFI_FILE_PROTOCOL *this ) {
	struct efi_file *file = container_of ( this, struct efi_file, file );

	/* Do nothing if this is the root */
	if ( ! file->image )
		return 0;

	/* Close file */
	DBGC ( file, "EFIFILE %s closed\n", efi_file_name ( file ) );
	image_put ( file->image );
	free ( file );

	return 0;
}

/**
 * Close and delete file
 *
 * @v this		EFI file
 * @ret efirc		EFI status code
 */
static EFI_STATUS EFIAPI efi_file_delete ( EFI_FILE_PROTOCOL *this ) {
	struct efi_file *file = container_of ( this, struct efi_file, file );

	DBGC ( file, "EFIFILE %s cannot be deleted\n", efi_file_name ( file ) );

	/* Close file */
	efi_file_close ( this );

	/* Warn of failure to delete */
	return EFI_WARN_DELETE_FAILURE;
}

/**
 * Return variable-length data structure
 *
 * @v base		Base data structure (starting with UINT64)
 * @v base_len		Length of base data structure
 * @v name		Name to append to base data structure
 * @v len		Length of data buffer
 * @v data		Data buffer
 * @ret efirc		EFI status code
 */
static EFI_STATUS efi_file_varlen ( UINT64 *base, size_t base_len,
				    const char *name, UINTN *len, VOID *data ) {
	size_t name_len;

	/* Calculate structure length */
	name_len = strlen ( name );
	*base = ( base_len + ( name_len + 1 /* NUL */ ) * sizeof ( wchar_t ) );
	if ( *len < *base ) {
		*len = *base;
		return EFI_BUFFER_TOO_SMALL;
	}

	/* Copy data to buffer */
	*len = *base;
	memcpy ( data, base, base_len );
	efi_snprintf ( ( data + base_len ), ( name_len + 1 /* NUL */ ),
		       "%s", name );

	return 0;
}

/**
 * Return file information structure
 *
 * @v image		Image, or NULL for the root directory
 * @v len		Length of data buffer
 * @v data		Data buffer
 * @ret efirc		EFI status code
 */
static EFI_STATUS efi_file_info ( struct image *image, UINTN *len,
				  VOID *data ) {
	EFI_FILE_INFO info;
	const char *name;

	/* Populate file information */
	memset ( &info, 0, sizeof ( info ) );
	if ( image ) {
		info.FileSize = image->len;
		info.PhysicalSize = image->len;
		info.Attribute = EFI_FILE_READ_ONLY;
		name = image->name;
	} else {
		info.Attribute = ( EFI_FILE_READ_ONLY | EFI_FILE_DIRECTORY );
		name = "";
	}

	return efi_file_varlen ( &info.Size, SIZE_OF_EFI_FILE_INFO, name,
				 len, data );
}

/**
 * Read directory entry
 *
 * @v file		EFI file
 * @v len		Length to read
 * @v data		Data buffer
 * @ret efirc		EFI status code
 */
static EFI_STATUS efi_file_read_dir ( struct efi_file *file, UINTN *len,
				      VOID *data ) {
	EFI_STATUS efirc;
	struct image *image;
	unsigned int index;

	/* Construct directory entry at current position */
	index = file->pos;
	for_each_image ( image ) {
		if ( index-- == 0 ) {
			efirc = efi_file_info ( image, len, data );
			if ( efirc == 0 )
				file->pos++;
			return efirc;
		}
	}

	/* No more entries */
	*len = 0;
	return 0;
}

/**
 * Read from file
 *
 * @v this		EFI file
 * @v len		Length to read
 * @v data		Data buffer
 * @ret efirc		EFI status code
 */
static EFI_STATUS EFIAPI efi_file_read ( EFI_FILE_PROTOCOL *this,
					 UINTN *len, VOID *data ) {
	struct efi_file *file = container_of ( this, struct efi_file, file );
	size_t remaining;

	/* If this is the root directory, then construct a directory entry */
	if ( ! file->image )
		return efi_file_read_dir ( file, len, data );

	/* Read from the file */
	remaining = ( file->image->len - file->pos );
	if ( *len > remaining )
		*len = remaining;
	DBGC ( file, "EFIFILE %s read [%#08zx,%#08zx)\n",
	       efi_file_name ( file ), file->pos,
	       ( ( size_t ) ( file->pos + *len ) ) );
	copy_from_user ( data, file->image->data, file->pos, *len );
	file->pos += *len;
	return 0;
}

/**
 * Write to file
 *
 * @v this		EFI file
 * @v len		Length to write
 * @v data		Data buffer
 * @ret efirc		EFI status code
 */
static EFI_STATUS EFIAPI efi_file_write ( EFI_FILE_PROTOCOL *this,
					  UINTN *len, VOID *data __unused ) {
	struct efi_file *file = container_of ( this, struct efi_file, file );

	DBGC ( file, "EFIFILE %s cannot write [%#08zx, %#08zx)\n",
	       efi_file_name ( file ), file->pos,
	       ( ( size_t ) ( file->pos + *len ) ) );
	return EFI_WRITE_PROTECTED;
}

/**
 * Set file position
 *
 * @v this		EFI file
 * @v position		New file position
 * @ret efirc		EFI status code
 */
static EFI_STATUS EFIAPI efi_file_set_position ( EFI_FILE_PROTOCOL *this,
						 UINT64 position ) {
	struct efi_file *file = container_of ( this, struct efi_file, file );

	/* If this is the root directory, reset to the start */
	if ( ! file->image ) {
		DBGC ( file, "EFIFILE root directory rewound\n" );
		file->pos = 0;
		return 0;
	}

	/* Check for the magic end-of-file value */
	if ( position == 0xffffffffffffffffULL )
		position = file->image->len;

	/* Fail if we attempt to seek past the end of the file (since
	 * we do not support writes).
	 */
	if ( position > file->image->len ) {
		DBGC ( file, "EFIFILE %s cannot seek to %#08llx of %#08zx\n",
		       efi_file_name ( file ), position, file->image->len );
		return EFI_UNSUPPORTED;
	}

	/* Set position */
	file->pos = position;
	DBGC ( file, "EFIFILE %s position set to %#08zx\n",
	       efi_file_name ( file ), file->pos );

	return 0;
}

/**
 * Get file position
 *
 * @v this		EFI file
 * @ret position	New file position
 * @ret efirc		EFI status code
 */
static EFI_STATUS EFIAPI efi_file_get_position ( EFI_FILE_PROTOCOL *this,
						 UINT64 *position ) {
	struct efi_file *file = container_of ( this, struct efi_file, file );

	*position = file->pos;
	return 0;
}

/**
 * Get file information
 *
 * @v this		EFI file
 * @v type		Type of information
 * @v len		Buffer size
 * @v data		Buffer
 * @ret efirc		EFI status code
 */
static EFI_STATUS EFIAPI efi_file_get_info ( EFI_FILE_PROTOCOL *this,
					     EFI_GUID *type,
					     UINTN *len, VOID *data ) {
	struct efi_file *file = container_of ( this, struct efi_file, file );
	EFI_FILE_SYSTEM_INFO fsinfo;
	struct image *image;

	/* Determine information to return */
	if ( memcmp ( type, &efi_file_info_id, sizeof ( *type ) ) == 0 ) {

		/* Get file information */
		DBGC ( file, "EFIFILE %s get file information\n",
		       efi_file_name ( file ) );
		return efi_file_info ( file->image, len, data );

	} else if ( memcmp ( type, &efi_file_system_info_id,
			     sizeof ( *type ) ) == 0 ) {

		/* Get file system information */
		DBGC ( file, "EFIFILE %s get file system information\n",
		       efi_file_name ( file ) );
		memset ( &fsinfo, 0, sizeof ( fsinfo ) );
		fsinfo.ReadOnly = 1;
		for_each_image ( image )
			fsinfo.VolumeSize += image->len;
		return efi_file_varlen ( &fsinfo.Size,
					 SIZE_OF_EFI_FILE_SYSTEM_INFO, "iPXE",
					 len, data );
	} else {

		DBGC ( file, "EFIFILE %s cannot get information of type %s\n",
		       efi_file_name ( file ), efi_guid_ntoa ( type ) );
		return EFI_UNSUPPORTED;
	}
}

/**
 * Set file information
 *
 * @v this		EFI file
 * @v type		Type of information
 * @v len		Buffer size
 * @v data		Buffer
 * @ret efirc		EFI status code
 */
static EFI_STATUS EFIAPI
efi_file_set_info ( EFI_FILE_PROTOCOL *this, EFI_GUID *type,
		    UINTN len __unused, VOID *data __unused ) {
	struct efi_file *file = container_of ( this, struct efi_file, file );

	DBGC ( file, "EFIFILE %s cannot set information of type %s\n",
	       efi_file_name ( file ), efi_guid_ntoa ( type ) );
	return EFI_WRITE_PROTECTED;
}

/**
 * Flush file modified data
 *
 * @v this		EFI file
 * @v type		Type of information
 * @v len		Buffer size
 * @v data		Buffer
 * @ret efirc		EFI status code
 */
static EFI_STATUS EFIAPI efi_file_flush ( EFI_FILE_PROTOCOL *this ) {
	struct efi_file *file = container_of ( this, struct efi_file, file );

	DBGC ( file, "EFIFILE %s flushed\n", efi_file_name ( file ) );
	return 0;
}

/** Root directory */
static struct efi_file efi_file_root = {
	.file = {
		.Revision = EFI_FILE_PROTOCOL_REVISION,
		.Open = efi_file_open,
		.Close = efi_file_close,
		.Delete = efi_file_delete,
		.Read = efi_file_read,
		.Write = efi_file_write,
		.GetPosition = efi_file_get_position,
		.SetPosition = efi_file_set_position,
		.GetInfo = efi_file_get_info,
		.SetInfo = efi_file_set_info,
		.Flush = efi_file_flush,
	},
	.image = NULL,
};

/**
 * Open root directory
 *
 * @v filesystem	EFI simple file system
 * @ret file		EFI file handle
 * @ret efirc		EFI status code
 */
static EFI_STATUS EFIAPI
efi_file_open_volume ( EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *filesystem __unused,
		       EFI_FILE_PROTOCOL **file ) {

	DBGC ( &efi_file_root, "EFIFILE open volume\n" );
	*file = &efi_file_root.file;
	return 0;
}

/** EFI simple file system protocol */
static EFI_SIMPLE_FILE_SYSTEM_PROTOCOL efi_simple_file_system_protocol = {
	.Revision = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_REVISION,
	.OpenVolume = efi_file_open_volume,
};

/** Dummy block I/O reset */
static EFI_STATUS EFIAPI
efi_block_io_reset ( EFI_BLOCK_IO_PROTOCOL *this __unused, BOOLEAN extended ) {

	DBGC ( &efi_file_root, "EFIFILE block %sreset\n",
	       ( extended ? "extended " : "" ) );
	return 0;
}

/** Dummy block I/O read */
static EFI_STATUS EFIAPI
efi_block_io_read_blocks ( EFI_BLOCK_IO_PROTOCOL *this __unused, UINT32 MediaId,
			   EFI_LBA lba, UINTN len, VOID *data ) {

	DBGC ( &efi_file_root, "EFIFILE block read ID %#08x LBA %#08llx -> "
	       "%p+%zx\n", MediaId, ( ( unsigned long long ) lba ),
	       data, ( ( size_t ) len ) );
	return EFI_NO_MEDIA;
}

/** Dummy block I/O write */
static EFI_STATUS EFIAPI
efi_block_io_write_blocks ( EFI_BLOCK_IO_PROTOCOL *this __unused,
			    UINT32 MediaId, EFI_LBA lba, UINTN len,
			    VOID *data ) {

	DBGC ( &efi_file_root, "EFIFILE block write ID %#08x LBA %#08llx <- "
	       "%p+%zx\n", MediaId, ( ( unsigned long long ) lba ),
	       data, ( ( size_t ) len ) );
	return EFI_NO_MEDIA;
}

/** Dummy block I/O flush */
static EFI_STATUS EFIAPI
efi_block_io_flush_blocks ( EFI_BLOCK_IO_PROTOCOL *this __unused ) {

	DBGC ( &efi_file_root, "EFIFILE block flush\n" );
	return 0;
}

/** Dummy block I/O media */
static EFI_BLOCK_IO_MEDIA efi_block_io_media = {
	.MediaId = EFI_MEDIA_ID_MAGIC,
	.MediaPresent = TRUE,
	.ReadOnly = TRUE,
	.BlockSize = 1,
};

/** Dummy EFI block I/O protocol */
static EFI_BLOCK_IO_PROTOCOL efi_block_io_protocol = {
	.Revision = EFI_BLOCK_IO_PROTOCOL_REVISION,
	.Media = &efi_block_io_media,
	.Reset = efi_block_io_reset,
	.ReadBlocks = efi_block_io_read_blocks,
	.WriteBlocks = efi_block_io_write_blocks,
	.FlushBlocks = efi_block_io_flush_blocks,
};

/** Dummy disk I/O read */
static EFI_STATUS EFIAPI
efi_disk_io_read_disk ( EFI_DISK_IO_PROTOCOL *this __unused, UINT32 MediaId,
			UINT64 offset, UINTN len, VOID *data ) {

	DBGC ( &efi_file_root, "EFIFILE disk read ID %#08x offset %#08llx -> "
	       "%p+%zx\n", MediaId, ( ( unsigned long long ) offset ),
	       data, ( ( size_t ) len ) );
	return EFI_NO_MEDIA;
}

/** Dummy disk I/O write */
static EFI_STATUS EFIAPI
efi_disk_io_write_disk ( EFI_DISK_IO_PROTOCOL *this __unused, UINT32 MediaId,
			 UINT64 offset, UINTN len, VOID *data ) {

	DBGC ( &efi_file_root, "EFIFILE disk write ID %#08x offset %#08llx <- "
	       "%p+%zx\n", MediaId, ( ( unsigned long long ) offset ),
	       data, ( ( size_t ) len ) );
	return EFI_NO_MEDIA;
}

/** Dummy EFI disk I/O protocol */
static EFI_DISK_IO_PROTOCOL efi_disk_io_protocol = {
	.Revision = EFI_DISK_IO_PROTOCOL_REVISION,
	.ReadDisk = efi_disk_io_read_disk,
	.WriteDisk = efi_disk_io_write_disk,
};

/**
 * Install EFI simple file system protocol
 *
 * @v handle		EFI handle
 * @ret rc		Return status code
 */
int efi_file_install ( EFI_HANDLE handle ) {
	EFI_BOOT_SERVICES *bs = efi_systab->BootServices;
	union {
		EFI_DISK_IO_PROTOCOL *diskio;
		void *interface;
	} diskio;
	EFI_STATUS efirc;
	int rc;

	/* Install the simple file system protocol, block I/O
	 * protocol, and disk I/O protocol.  We don't have a block
	 * device, but large parts of the EDK2 codebase make the
	 * assumption that file systems are normally attached to block
	 * devices, and so we create a dummy block device on the same
	 * handle just to keep things looking normal.
	 */
	if ( ( efirc = bs->InstallMultipleProtocolInterfaces (
			&handle,
			&efi_block_io_protocol_guid,
			&efi_block_io_protocol,
			&efi_disk_io_protocol_guid,
			&efi_disk_io_protocol,
			&efi_simple_file_system_protocol_guid,
			&efi_simple_file_system_protocol, NULL ) ) != 0 ) {
		rc = -EEFI ( efirc );
		DBGC ( handle, "Could not install simple file system "
		       "protocols: %s\n", strerror ( rc ) );
		goto err_install;
	}

	/* The FAT filesystem driver has a bug: if a block device
	 * contains no FAT filesystem but does have an
	 * EFI_SIMPLE_FILE_SYSTEM_PROTOCOL instance, the FAT driver
	 * will assume that it must have previously installed the
	 * EFI_SIMPLE_FILE_SYSTEM_PROTOCOL.  This causes the FAT
	 * driver to claim control of our device, and to refuse to
	 * stop driving it, which prevents us from later uninstalling
	 * correctly.
	 *
	 * Work around this bug by opening the disk I/O protocol
	 * ourselves, thereby preventing the FAT driver from opening
	 * it.
	 *
	 * Note that the alternative approach of opening the block I/O
	 * protocol (and thereby in theory preventing DiskIo from
	 * attaching to the block I/O protocol) causes an endless loop
	 * of calls to our DRIVER_STOP method when starting the EFI
	 * shell.  I have no idea why this is.
	 */
	if ( ( efirc = bs->OpenProtocol ( handle, &efi_disk_io_protocol_guid,
					  &diskio.interface, efi_image_handle,
					  handle,
					  EFI_OPEN_PROTOCOL_BY_DRIVER ) ) != 0){
		rc = -EEFI ( efirc );
		DBGC ( handle, "Could not open disk I/O protocol: %s\n",
		       strerror ( rc ) );
		DBGC_EFI_OPENERS ( handle, handle, &efi_disk_io_protocol_guid );
		goto err_open;
	}
	assert ( diskio.diskio == &efi_disk_io_protocol );

	return 0;

	bs->CloseProtocol ( handle, &efi_disk_io_protocol_guid,
			    efi_image_handle, handle );
 err_open:
	bs->UninstallMultipleProtocolInterfaces (
			handle,
			&efi_simple_file_system_protocol_guid,
			&efi_simple_file_system_protocol,
			&efi_disk_io_protocol_guid,
			&efi_disk_io_protocol,
			&efi_block_io_protocol_guid,
			&efi_block_io_protocol, NULL );
 err_install:
	return rc;
}

/**
 * Uninstall EFI simple file system protocol
 *
 * @v handle		EFI handle
 */
void efi_file_uninstall ( EFI_HANDLE handle ) {
	EFI_BOOT_SERVICES *bs = efi_systab->BootServices;
	EFI_STATUS efirc;
	int rc;

	/* Close our own disk I/O protocol */
	bs->CloseProtocol ( handle, &efi_disk_io_protocol_guid,
			    efi_image_handle, handle );

	/* We must install the file system protocol first, since
	 * otherwise the EDK2 code will attempt to helpfully uninstall
	 * it when the block I/O protocol is uninstalled, leading to a
	 * system lock-up.
	 */
	if ( ( efirc = bs->UninstallMultipleProtocolInterfaces (
			handle,
			&efi_simple_file_system_protocol_guid,
			&efi_simple_file_system_protocol,
			&efi_disk_io_protocol_guid,
			&efi_disk_io_protocol,
			&efi_block_io_protocol_guid,
			&efi_block_io_protocol, NULL ) ) != 0 ) {
		rc = -EEFI ( efirc );
		DBGC ( handle, "Could not uninstall simple file system "
		       "protocols: %s\n", strerror ( rc ) );
		/* Oh dear */
	}
}
