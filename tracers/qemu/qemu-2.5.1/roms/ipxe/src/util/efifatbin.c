/*
 * Copyright (C) 2014 Michael Brown <mbrown@fensystems.co.uk>.
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
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <getopt.h>
#include <ipxe/efi/efi.h>
#include <ipxe/efi/IndustryStandard/PeImage.h>

#define eprintf(...) fprintf ( stderr, __VA_ARGS__ )

/** Command-line options */
struct options {
};

/** EFI fat binary file header */
struct efifatbin_file_header {
	/** Signature */
	uint32_t signature;
	/** Count */
	uint32_t count;
} __attribute__ (( packed ));

/** EFI fat binary signature */
#define EFIFATBIN_SIGNATURE 0x0ef1fab9

/** EFI fat binary image header */
struct efifatbin_image_header {
	/** Flags */
	uint64_t flags;
	/** Offset */
	uint32_t offset;
	/** Length */
	uint32_t len;
	/** Padding */
	uint32_t pad;
} __attribute__ (( packed ));

/** EFI fat binary default flags */
#define EFIFATBIN_FLAGS 0x0000000300000007ULL

/** EFI fat binary 64-bit flag */
#define EFIFATBIN_64BIT 0x0000000001000000ULL

/**
 * Allocate memory
 *
 * @v len		Length of memory to allocate
 * @ret ptr		Pointer to allocated memory
 */
static void * xmalloc ( size_t len ) {
	void *ptr;

	ptr = malloc ( len );
	if ( ! ptr ) {
		eprintf ( "Could not allocate %zd bytes\n", len );
		exit ( 1 );
	}

	return ptr;
}

/**
 * Generate EFI fat binary
 *
 * @v count		Number of input files
 * @v infile_names	Input filenames
 * @v outfile_name	Output filename
 */
static void make_efifatbin ( unsigned int count, char **infile_names,
			     const char *outfile_name ) {
	FILE *infile[count];
	FILE *outfile;
	struct stat stat[count];
	void *buf[count];
	struct efifatbin_file_header file_header;
	struct efifatbin_image_header header[count];
	size_t offset;
	EFI_IMAGE_DOS_HEADER *dos;
	union {
		EFI_IMAGE_NT_HEADERS32 nt32;
		EFI_IMAGE_NT_HEADERS64 nt64;
	} *nt;
	unsigned int i;

	/* Generate file header */
	file_header.signature = EFIFATBIN_SIGNATURE;
	file_header.count = count;
	offset = ( sizeof ( file_header ) + sizeof ( header ) );

	/* Process input files */
	for ( i = 0 ; i < count ; i++ ) {

		/* Open input file */
		infile[i] = fopen ( infile_names[i], "r" );
		if ( ! infile[i] ) {
			eprintf ( "Could not open %s for reading: %s\n",
				  infile_names[i], strerror ( errno ) );
			exit ( 1 );
		}

		/* Determine PE file size */
		if ( fstat ( fileno ( infile[i] ), &stat[i] ) != 0 ) {
			eprintf ( "Could not stat %s: %s\n",
				  infile_names[i], strerror ( errno ) );
			exit ( 1 );
		}

		/* Allocate buffer and read in PE file */
		buf[i] = xmalloc ( stat[i].st_size );
		if ( fread ( buf[i], stat[i].st_size, 1, infile[i] ) != 1 ) {
			eprintf ( "Could not read %s: %s\n",
				  infile_names[i], strerror ( errno ) );
			exit ( 1 );
		}

		/* Close input file */
		fclose ( infile[i] );

		/* Generate image header */
		header[i].flags = EFIFATBIN_FLAGS;
		header[i].offset = offset;
		header[i].len = stat[i].st_size;
		header[i].pad = 0;

		/* Determine architecture */
		dos = buf[i];
		nt = ( buf[i] + dos->e_lfanew );
		if ( nt->nt32.FileHeader.Machine == EFI_IMAGE_MACHINE_X64 )
			header[i].flags |= EFIFATBIN_64BIT;

		/* Allow space for this image */
		offset += stat[i].st_size;
	}

	/* Open output file */
	outfile = fopen ( outfile_name, "w" );
	if ( ! outfile ) {
		eprintf ( "Could not open %s for writing: %s\n",
			  outfile_name, strerror ( errno ) );
		exit ( 1 );
	}

	/* Write fat binary header */
	if ( fwrite ( &file_header, sizeof ( file_header ), 1, outfile ) != 1 ){
		eprintf ( "Could not write %s: %s\n",
			  outfile_name, strerror ( errno ) );
		exit ( 1 );
	}
	for ( i = 0 ; i < count ; i++ ) {
		if ( fwrite ( &header[i], sizeof ( header[i] ), 1,
			      outfile ) != 1 ) {
			eprintf ( "Could not write %s: %s\n",
				  outfile_name, strerror ( errno ) );
			exit ( 1 );
		}
	}

	/* Write images */
	for ( i = 0 ; i < count ; i++ ) {
		if ( fwrite ( buf[i], stat[i].st_size, 1, outfile ) != 1 ) {
			eprintf ( "Could not write %s: %s\n",
				  outfile_name, strerror ( errno ) );
			exit ( 1 );
		}
	}

	/* Close output file */
	fclose ( outfile );
}

/**
 * Print help
 *
 * @v program_name	Program name
 */
static void print_help ( const char *program_name ) {
	eprintf ( "Syntax: %s infile [infile...] outfile\n", program_name );
}

/**
 * Parse command-line options
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @v opts		Options structure to populate
 */
static int parse_options ( const int argc, char **argv,
			   struct options *opts __attribute__ (( unused )) ) {
	int c;

	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			{ "help", 0, NULL, 'h' },
			{ 0, 0, 0, 0 }
		};

		if ( ( c = getopt_long ( argc, argv, "h",
					 long_options,
					 &option_index ) ) == -1 ) {
			break;
		}

		switch ( c ) {
		case 'h':
			print_help ( argv[0] );
			exit ( 0 );
		case '?':
		default:
			exit ( 2 );
		}
	}
	return optind;
}

int main ( int argc, char **argv ) {
	struct options opts;
	int infile_index;
	int outfile_index;
	int count;

	/* Parse command-line arguments */
	memset ( &opts, 0, sizeof ( opts ) );
	infile_index = parse_options ( argc, argv, &opts );
	outfile_index = ( argc - 1 );
	count = ( outfile_index - infile_index );
	if ( count <= 0 ) {
		print_help ( argv[0] );
		exit ( 2 );
	}

	/* Generate fat binary */
	make_efifatbin ( count, &argv[infile_index], argv[outfile_index] );

	return 0;
}
