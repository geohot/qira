#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <lzma.h>

#define DEBUG 0

/* LZMA filter choices.  Must match those used by unlzma.S */
#define LZMA_LC 2
#define LZMA_LP 0
#define LZMA_PB 0

/* LZMA preset choice.  This is a policy decision */
#define LZMA_PRESET ( LZMA_PRESET_DEFAULT | LZMA_PRESET_EXTREME )

struct input_file {
	void *buf;
	size_t len;
};

struct output_file {
	void *buf;
	size_t len;
	size_t hdr_len;
	size_t max_len;
};

struct zinfo_common {
	char type[4];
	char pad[12];
};

struct zinfo_copy {
	char type[4];
	uint32_t offset;
	uint32_t len;
	uint32_t align;
};

struct zinfo_pack {
	char type[4];
	uint32_t offset;
	uint32_t len;
	uint32_t align;
};

struct zinfo_payload {
	char type[4];
	uint32_t pad1;
	uint32_t pad2;
	uint32_t align;
};

struct zinfo_add {
	char type[4];
	uint32_t offset;
	uint32_t divisor;
	uint32_t pad;
};

union zinfo_record {
	struct zinfo_common common;
	struct zinfo_copy copy;
	struct zinfo_pack pack;
	struct zinfo_payload payload;
	struct zinfo_add add;
};

struct zinfo_file {
	union zinfo_record *zinfo;
	unsigned int num_entries;
};

static unsigned long align ( unsigned long value, unsigned long align ) {
	return ( ( value + align - 1 ) & ~( align - 1 ) );
}

static int read_file ( const char *filename, void **buf, size_t *len ) {
	FILE *file;
	struct stat stat;

	file = fopen ( filename, "r" );
	if ( ! file ) {
		fprintf ( stderr, "Could not open %s: %s\n", filename,
			  strerror ( errno ) );
		goto err;
	}

	if ( fstat ( fileno ( file ), &stat ) < 0 ) {
		fprintf ( stderr, "Could not stat %s: %s\n", filename,
			  strerror ( errno ) );
		goto err;
	}

	*len = stat.st_size;
	*buf = malloc ( *len );
	if ( ! *buf ) {
		fprintf ( stderr, "Could not malloc() %zd bytes for %s: %s\n",
			  *len, filename, strerror ( errno ) );
		goto err;
	}

	if ( fread ( *buf, 1, *len, file ) != *len ) {
		fprintf ( stderr, "Could not read %zd bytes from %s: %s\n",
			  *len, filename, strerror ( errno ) );
		goto err;
	}

	fclose ( file );
	return 0;

 err:
	if ( file )
		fclose ( file );
	return -1;
}

static int read_input_file ( const char *filename,
			     struct input_file *input ) {
	return read_file ( filename, &input->buf, &input->len );
}

static int read_zinfo_file ( const char *filename,
			     struct zinfo_file *zinfo ) {
	void *buf;
	size_t len;

	if ( read_file ( filename, &buf, &len ) < 0 )
		return -1;

	if ( ( len % sizeof ( *(zinfo->zinfo) ) ) != 0 ) {
		fprintf ( stderr, ".zinfo file %s has invalid length %zd\n",
			  filename, len );
		return -1;
	}

	zinfo->zinfo = buf;
	zinfo->num_entries = ( len / sizeof ( *(zinfo->zinfo) ) );
	return 0;
}

static int alloc_output_file ( size_t max_len, struct output_file *output ) {
	output->len = 0;
	output->max_len = ( max_len );
	output->buf = malloc ( max_len );
	if ( ! output->buf ) {
		fprintf ( stderr, "Could not allocate %zd bytes for output\n",
			  max_len );
		return -1;
	}
	memset ( output->buf, 0xff, max_len );
	return 0;
}

static int process_zinfo_copy ( struct input_file *input,
				struct output_file *output,
				union zinfo_record *zinfo ) {
	struct zinfo_copy *copy = &zinfo->copy;
	size_t offset = copy->offset;
	size_t len = copy->len;

	if ( ( offset + len ) > input->len ) {
		fprintf ( stderr, "Input buffer overrun on copy\n" );
		return -1;
	}

	output->len = align ( output->len, copy->align );
	if ( ( output->len + len ) > output->max_len ) {
		fprintf ( stderr, "Output buffer overrun on copy\n" );
		return -1;
	}

	if ( DEBUG ) {
		fprintf ( stderr, "COPY [%#zx,%#zx) to [%#zx,%#zx)\n",
			  offset, ( offset + len ), output->len,
			  ( output->len + len ) );
	}

	memcpy ( ( output->buf + output->len ),
		 ( input->buf + offset ), len );
	output->len += len;
	return 0;
}

#define OPCODE_CALL 0xe8
#define OPCODE_JMP 0xe9

static void bcj_filter ( void *data, size_t len ) {
	struct {
		uint8_t opcode;
		int32_t target;
	} __attribute__ (( packed )) *jump;
	ssize_t limit = ( len - sizeof ( *jump ) );
	ssize_t offset;

	/* liblzma does include an x86 BCJ filter, but it's hideously
	 * convoluted and undocumented.  This BCJ filter is
	 * substantially simpler and achieves the same compression (at
	 * the cost of requiring the decompressor to know the size of
	 * the decompressed data, which we already have in iPXE).
	 */
	for ( offset = 0 ; offset <= limit ; offset++ ) {
		jump = ( data + offset );

		/* Skip instructions that are not followed by a rel32 address */
		if ( ( jump->opcode != OPCODE_CALL ) &&
		     ( jump->opcode != OPCODE_JMP ) )
			continue;

		/* Convert rel32 address to an absolute address.  To
		 * avoid false positives (which damage the compression
		 * ratio), we should check that the jump target is
		 * within the range [0,limit).
		 *
		 * Some output values would then end up being mapped
		 * from two distinct input values, making the
		 * transformation irreversible.  To solve this, we
		 * transform such values back into the part of the
		 * range which would otherwise correspond to no input
		 * values.
		 */
		if ( ( jump->target >= -offset ) &&
		     ( jump->target < ( limit - offset ) ) ) {
			/* Convert relative addresses in the range
			 * [-offset,limit-offset) to absolute
			 * addresses in the range [0,limit).
			 */
			jump->target += offset;
		} else if ( ( jump->target >= ( limit - offset ) ) &&
			    ( jump->target < limit ) ) {
			/* Convert positive numbers in the range
			 * [limit-offset,limit) to negative numbers in
			 * the range [-offset,0).
			 */
			jump->target -= limit;
		}
		offset += sizeof ( jump->target );
	};
}

static int process_zinfo_pack ( struct input_file *input,
				struct output_file *output,
				union zinfo_record *zinfo ) {
	struct zinfo_pack *pack = &zinfo->pack;
	size_t offset = pack->offset;
	size_t len = pack->len;
	size_t packed_len = 0;
	size_t remaining = ( output->max_len - output->len );
	lzma_options_lzma options;
	const lzma_filter filters[] = {
		{ .id = LZMA_FILTER_LZMA1, .options = &options },
		{ .id = LZMA_VLI_UNKNOWN }
	};

	if ( ( offset + len ) > input->len ) {
		fprintf ( stderr, "Input buffer overrun on pack\n" );
		return -1;
	}

	output->len = align ( output->len, pack->align );
	if ( output->len > output->max_len ) {
		fprintf ( stderr, "Output buffer overrun on pack\n" );
		return -1;
	}

	bcj_filter ( ( input->buf + offset ), len );

	lzma_lzma_preset ( &options, LZMA_PRESET );
	options.lc = LZMA_LC;
	options.lp = LZMA_LP;
	options.pb = LZMA_PB;
	if ( lzma_raw_buffer_encode ( filters, NULL, ( input->buf + offset ),
				      len, ( output->buf + output->len ),
				      &packed_len, remaining ) != LZMA_OK ) {
		fprintf ( stderr, "Compression failure\n" );
		return -1;
	}

	if ( DEBUG ) {
		fprintf ( stderr, "PACK [%#zx,%#zx) to [%#zx,%#zx)\n",
			  offset, ( offset + len ), output->len,
			  ( output->len + packed_len ) );
	}

	output->len += packed_len;
	if ( output->len > output->max_len ) {
		fprintf ( stderr, "Output buffer overrun on pack\n" );
		return -1;
	}

	return 0;
}

static int process_zinfo_payl ( struct input_file *input
					__attribute__ (( unused )),
				struct output_file *output,
				union zinfo_record *zinfo ) {
	struct zinfo_payload *payload = &zinfo->payload;

	output->len = align ( output->len, payload->align );
	output->hdr_len = output->len;

	if ( DEBUG ) {
		fprintf ( stderr, "PAYL at %#zx\n", output->hdr_len );
	}
	return 0;
}

static int process_zinfo_add ( struct input_file *input
					__attribute__ (( unused )),
			       struct output_file *output,
			       size_t len,
			       struct zinfo_add *add, size_t offset,
			       size_t datasize ) {
	void *target;
	signed long addend;
	unsigned long size;
	signed long val;
	unsigned long mask;

	offset += add->offset;
	if ( ( offset + datasize ) > output->len ) {
		fprintf ( stderr, "Add at %#zx outside output buffer\n",
			  offset );
		return -1;
	}

	target = ( output->buf + offset );
	size = ( align ( len, add->divisor ) / add->divisor );

	switch ( datasize ) {
	case 1:
		addend = *( ( int8_t * ) target );
		break;
	case 2:
		addend = *( ( int16_t * ) target );
		break;
	case 4:
		addend = *( ( int32_t * ) target );
		break;
	default:
		fprintf ( stderr, "Unsupported add datasize %zd\n",
			  datasize );
		return -1;
	}

	val = size + addend;

	/* The result of 1UL << ( 8 * sizeof(unsigned long) ) is undefined */
	mask = ( ( datasize < sizeof ( mask ) ) ?
		 ( ( 1UL << ( 8 * datasize ) ) - 1 ) : ~0UL );

	if ( val < 0 ) {
		fprintf ( stderr, "Add %s%#x+%#lx at %#zx %sflows field\n",
			  ( ( addend < 0 ) ? "-" : "" ), abs ( addend ), size,
			  offset, ( ( addend < 0 ) ? "under" : "over" ) );
		return -1;
	}

	if ( val & ~mask ) {
		fprintf ( stderr, "Add %s%#x+%#lx at %#zx overflows %zd-byte "
			  "field (%d bytes too big)\n",
			  ( ( addend < 0 ) ? "-" : "" ), abs ( addend ), size,
			  offset, datasize,
			  ( int )( ( val - mask - 1 ) * add->divisor ) );
		return -1;
	}

	switch ( datasize ) {
	case 1:
		*( ( uint8_t * ) target ) = val;
		break;
	case 2:
		*( ( uint16_t * ) target ) = val;
		break;
	case 4:
		*( ( uint32_t * ) target ) = val;
		break;
	}

	if ( DEBUG ) {
		fprintf ( stderr, "ADDx [%#zx,%#zx) (%s%#x+(%#zx/%#x)) = "
			  "%#lx\n", offset, ( offset + datasize ),
			  ( ( addend < 0 ) ? "-" : "" ), abs ( addend ),
			  len, add->divisor, val );
	}

	return 0;
}

static int process_zinfo_addb ( struct input_file *input,
				struct output_file *output,
				union zinfo_record *zinfo ) {
	return process_zinfo_add ( input, output, output->len,
				   &zinfo->add, 0, 1 );
}

static int process_zinfo_addw ( struct input_file *input,
				struct output_file *output,
				union zinfo_record *zinfo ) {
	return process_zinfo_add ( input, output, output->len,
				   &zinfo->add, 0, 2 );
}

static int process_zinfo_addl ( struct input_file *input,
				struct output_file *output,
				union zinfo_record *zinfo ) {
	return process_zinfo_add ( input, output, output->len,
				   &zinfo->add, 0, 4 );
}

static int process_zinfo_adhb ( struct input_file *input,
				struct output_file *output,
				union zinfo_record *zinfo ) {
	return process_zinfo_add ( input, output, output->hdr_len,
				   &zinfo->add, 0, 1 );
}

static int process_zinfo_adhw ( struct input_file *input,
				struct output_file *output,
				union zinfo_record *zinfo ) {
	return process_zinfo_add ( input, output, output->hdr_len,
				   &zinfo->add, 0, 2 );
}

static int process_zinfo_adhl ( struct input_file *input,
				struct output_file *output,
				union zinfo_record *zinfo ) {
	return process_zinfo_add ( input, output, output->hdr_len,
				   &zinfo->add, 0, 4 );
}

static int process_zinfo_adpb ( struct input_file *input,
				struct output_file *output,
				union zinfo_record *zinfo ) {
	return process_zinfo_add ( input, output,
				   ( output->len - output->hdr_len ),
				   &zinfo->add, 0, 1 );
}

static int process_zinfo_adpw ( struct input_file *input,
				struct output_file *output,
				union zinfo_record *zinfo ) {
	return process_zinfo_add ( input, output,
				   ( output->len - output->hdr_len ),
				   &zinfo->add, 0, 2 );
}

static int process_zinfo_adpl ( struct input_file *input,
				struct output_file *output,
				union zinfo_record *zinfo ) {
	return process_zinfo_add ( input, output,
				   ( output->len - output->hdr_len ),
				   &zinfo->add, 0, 4 );
}

static int process_zinfo_appb ( struct input_file *input,
				struct output_file *output,
				union zinfo_record *zinfo ) {
	return process_zinfo_add ( input, output,
				   ( output->len - output->hdr_len ),
				   &zinfo->add, output->hdr_len, 1 );
}

static int process_zinfo_appw ( struct input_file *input,
				struct output_file *output,
				union zinfo_record *zinfo ) {
	return process_zinfo_add ( input, output,
				   ( output->len - output->hdr_len ),
				   &zinfo->add, output->hdr_len, 2 );
}

static int process_zinfo_appl ( struct input_file *input,
				struct output_file *output,
				union zinfo_record *zinfo ) {
	return process_zinfo_add ( input, output,
				   ( output->len - output->hdr_len ),
				   &zinfo->add, output->hdr_len, 4 );
}

struct zinfo_processor {
	char *type;
	int ( * process ) ( struct input_file *input,
			    struct output_file *output,
			    union zinfo_record *zinfo );
};

static struct zinfo_processor zinfo_processors[] = {
	{ "COPY", process_zinfo_copy },
	{ "PACK", process_zinfo_pack },
	{ "PAYL", process_zinfo_payl },
	{ "ADDB", process_zinfo_addb },
	{ "ADDW", process_zinfo_addw },
	{ "ADDL", process_zinfo_addl },
	{ "ADHB", process_zinfo_adhb },
	{ "ADHW", process_zinfo_adhw },
	{ "ADHL", process_zinfo_adhl },
	{ "ADPB", process_zinfo_adpb },
	{ "ADPW", process_zinfo_adpw },
	{ "ADPL", process_zinfo_adpl },
	{ "APPB", process_zinfo_appb },
	{ "APPW", process_zinfo_appw },
	{ "APPL", process_zinfo_appl },
};

static int process_zinfo ( struct input_file *input,
			   struct output_file *output,
			   union zinfo_record *zinfo ) {
	struct zinfo_common *common = &zinfo->common;
	struct zinfo_processor *processor;
	char type[ sizeof ( common->type ) + 1 ] = "";
	unsigned int i;

	strncat ( type, common->type, sizeof ( type ) - 1 );
	for ( i = 0 ; i < ( sizeof ( zinfo_processors ) /
			    sizeof ( zinfo_processors[0] ) ) ; i++ ) {
		processor = &zinfo_processors[i];
		if ( strcmp ( processor->type, type ) == 0 )
			return processor->process ( input, output, zinfo );
	}

	fprintf ( stderr, "Unknown zinfo record type \"%s\"\n", &type[0] );
	return -1;
}

static int write_output_file ( struct output_file *output ) {
	if ( fwrite ( output->buf, 1, output->len, stdout ) != output->len ) {
		fprintf ( stderr, "Could not write %zd bytes of output: %s\n",
			  output->len, strerror ( errno ) );
		return -1;
	}
	return 0;
}

int main ( int argc, char **argv ) {
	struct input_file input;
	struct output_file output;
	struct zinfo_file zinfo;
	unsigned int i;

	if ( argc != 3 ) {
		fprintf ( stderr, "Syntax: %s file.bin file.zinfo "
			  "> file.zbin\n", argv[0] );
		exit ( 1 );
	}

	if ( read_input_file ( argv[1], &input ) < 0 )
		exit ( 1 );
	if ( read_zinfo_file ( argv[2], &zinfo ) < 0 )
		exit ( 1 );
	if ( alloc_output_file ( ( input.len * 4 ), &output ) < 0 )
		exit ( 1 );

	for ( i = 0 ; i < zinfo.num_entries ; i++ ) {
		if ( process_zinfo ( &input, &output,
				     &zinfo.zinfo[i] ) < 0 )
			exit ( 1 );
	}

	if ( write_output_file ( &output ) < 0 )
		exit ( 1 );

	return 0;
}
