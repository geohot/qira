#include <errno.h>
#include <assert.h>
#include <realmode.h>
#include <memsizes.h>
#include <basemem_packet.h>
#include <ipxe/uaccess.h>
#include <ipxe/segment.h>
#include <ipxe/init.h>
#include <ipxe/netdevice.h>
#include <ipxe/fakedhcp.h>
#include <ipxe/image.h>
#include <ipxe/features.h>
#include <ipxe/version.h>

/** @file
 *
 * NBI image format.
 *
 * The Net Boot Image format is defined by the "Draft Net Boot Image
 * Proposal 0.3" by Jamie Honan, Gero Kuhlmann and Ken Yap.  It is now
 * considered to be a legacy format, but it still included because a
 * large amount of software (e.g. nymph, LTSP) makes use of NBI files.
 *
 * Etherboot does not implement the INT 78 callback interface
 * described by the NBI specification.  For a callback interface on
 * x86 architecture, use PXE.
 *
 */

FEATURE ( FEATURE_IMAGE, "NBI", DHCP_EB_FEATURE_NBI, 1 );

/**
 * An NBI image header
 *
 * Note that the length field uses a peculiar encoding; use the
 * NBI_LENGTH() macro to decode the actual header length.
 *
 */
struct imgheader {
	unsigned long magic;		/**< Magic number (NBI_MAGIC) */
	union {
		unsigned char length;	/**< Nibble-coded header length */
		unsigned long flags;	/**< Image flags */
	};
	segoff_t location;		/**< 16-bit seg:off header location */
	union {
		segoff_t segoff;	/**< 16-bit seg:off entry point */
		unsigned long linear;	/**< 32-bit entry point */
	} execaddr;
} __attribute__ (( packed ));

/** NBI magic number */
#define NBI_MAGIC 0x1B031336UL

/* Interpretation of the "length" fields */
#define NBI_NONVENDOR_LENGTH(len)	( ( (len) & 0x0f ) << 2 )
#define NBI_VENDOR_LENGTH(len)		( ( (len) & 0xf0 ) >> 2 )
#define NBI_LENGTH(len) ( NBI_NONVENDOR_LENGTH(len) + NBI_VENDOR_LENGTH(len) )

/* Interpretation of the "flags" fields */
#define	NBI_PROGRAM_RETURNS(flags)	( (flags) & ( 1 << 8 ) )
#define	NBI_LINEAR_EXEC_ADDR(flags)	( (flags) & ( 1 << 31 ) )

/** NBI header length */
#define NBI_HEADER_LENGTH	512

/**
 * An NBI segment header
 *
 * Note that the length field uses a peculiar encoding; use the
 * NBI_LENGTH() macro to decode the actual header length.
 *
 */
struct segheader {
	unsigned char length;		/**< Nibble-coded header length */
	unsigned char vendortag;	/**< Vendor-defined private tag */
	unsigned char reserved;
	unsigned char flags;		/**< Segment flags */
	unsigned long loadaddr;		/**< Load address */
	unsigned long imglength;	/**< Segment length in NBI file */
	unsigned long memlength;	/**< Segment length in memory */
};

/* Interpretation of the "flags" fields */
#define NBI_LOADADDR_FLAGS(flags)	( (flags) & 0x03 )
#define NBI_LOADADDR_ABS		0x00
#define NBI_LOADADDR_AFTER		0x01
#define NBI_LOADADDR_END		0x02
#define NBI_LOADADDR_BEFORE		0x03
#define NBI_LAST_SEGHEADER(flags)	( (flags) & ( 1 << 2 ) )

/* Define a type for passing info to a loaded program */
struct ebinfo {
	uint8_t  major, minor;  /* Version */
	uint16_t flags;         /* Bit flags */
};

/**
 * Prepare a segment for an NBI image
 *
 * @v image		NBI image
 * @v offset		Offset within NBI image
 * @v filesz		Length of initialised-data portion of the segment
 * @v memsz		Total length of the segment
 * @v src		Source for initialised data
 * @ret rc		Return status code
 */
static int nbi_prepare_segment ( struct image *image, size_t offset __unused,
				 userptr_t dest, size_t filesz, size_t memsz ){
	int rc;

	if ( ( rc = prep_segment ( dest, filesz, memsz ) ) != 0 ) {
		DBGC ( image, "NBI %p could not prepare segment: %s\n",
		       image, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Load a segment for an NBI image
 *
 * @v image		NBI image
 * @v offset		Offset within NBI image
 * @v filesz		Length of initialised-data portion of the segment
 * @v memsz		Total length of the segment
 * @v src		Source for initialised data
 * @ret rc		Return status code
 */
static int nbi_load_segment ( struct image *image, size_t offset,
			      userptr_t dest, size_t filesz,
			      size_t memsz __unused ) {
	memcpy_user ( dest, 0, image->data, offset, filesz );
	return 0;
}

/**
 * Process segments of an NBI image
 *
 * @v image		NBI image
 * @v imgheader		Image header information
 * @v process		Function to call for each segment
 * @ret rc		Return status code
 */
static int nbi_process_segments ( struct image *image,
				  struct imgheader *imgheader,
				  int ( * process ) ( struct image *image,
						      size_t offset,
						      userptr_t dest,
						      size_t filesz,
						      size_t memsz ) ) {
	struct segheader sh;
	size_t offset = 0;
	size_t sh_off;
	userptr_t dest;
	size_t filesz;
	size_t memsz;
	int rc;
	
	/* Copy image header to target location */
	dest = real_to_user ( imgheader->location.segment,
			      imgheader->location.offset );
	filesz = memsz = NBI_HEADER_LENGTH;
	if ( ( rc = process ( image, offset, dest, filesz, memsz ) ) != 0 )
		return rc;
	offset += filesz;

	/* Process segments in turn */
	sh_off = NBI_LENGTH ( imgheader->length );
	do {
		/* Read segment header */
		copy_from_user ( &sh, image->data, sh_off, sizeof ( sh ) );
		if ( sh.length == 0 ) {
			/* Avoid infinite loop? */
			DBGC ( image, "NBI %p invalid segheader length 0\n",
			       image );
			return -ENOEXEC;
		}
		
		/* Calculate segment load address */
		switch ( NBI_LOADADDR_FLAGS ( sh.flags ) ) {
		case NBI_LOADADDR_ABS:
			dest = phys_to_user ( sh.loadaddr );
			break;
		case NBI_LOADADDR_AFTER:
			dest = userptr_add ( dest, memsz + sh.loadaddr );
			break;
		case NBI_LOADADDR_BEFORE:
			dest = userptr_add ( dest, -sh.loadaddr );
			break;
		case NBI_LOADADDR_END:
			/* Not correct according to the spec, but
			 * maintains backwards compatibility with
			 * previous versions of Etherboot.
			 */
			dest = phys_to_user ( ( extmemsize() + 1024 ) * 1024
					      - sh.loadaddr );
			break;
		default:
			/* Cannot be reached */
			assert ( 0 );
		}

		/* Process this segment */
		filesz = sh.imglength;
		memsz = sh.memlength;
		if ( ( offset + filesz ) > image->len ) {
			DBGC ( image, "NBI %p segment outside file\n", image );
			return -ENOEXEC;
		}
		if ( ( rc = process ( image, offset, dest,
				      filesz, memsz ) ) != 0 ) {
			return rc;
		}
		offset += filesz;

		/* Next segheader */
		sh_off += NBI_LENGTH ( sh.length );
		if ( sh_off >= NBI_HEADER_LENGTH ) {
			DBGC ( image, "NBI %p header overflow\n", image );
			return -ENOEXEC;
		}

	} while ( ! NBI_LAST_SEGHEADER ( sh.flags ) );

	if ( offset != image->len ) {
		DBGC ( image, "NBI %p length wrong (file %zd, metadata %zd)\n",
		       image, image->len, offset );
		return -ENOEXEC;
	}

	return 0;
}

/**
 * Boot a 16-bit NBI image
 *
 * @v imgheader		Image header information
 * @ret rc		Return status code, if image returns
 */
static int nbi_boot16 ( struct image *image, struct imgheader *imgheader ) {
	int discard_D, discard_S, discard_b;
	int rc;

	DBGC ( image, "NBI %p executing 16-bit image at %04x:%04x\n", image,
	       imgheader->execaddr.segoff.segment,
	       imgheader->execaddr.segoff.offset );

	__asm__ __volatile__ (
		REAL_CODE ( "pushl %%ebp\n\t"	/* gcc bug */
			    "pushw %%ds\n\t"	/* far pointer to bootp data */
			    "pushw %%bx\n\t"
			    "pushl %%esi\n\t"	/* location */
			    "pushw %%cs\n\t"	/* lcall execaddr */
			    "call 1f\n\t"
			    "jmp 2f\n\t"
			    "\n1:\n\t"
			    "pushl %%edi\n\t"
			    "lret\n\t"
			    "\n2:\n\t"
			    "addw $8,%%sp\n\t"	/* clean up stack */
			    "popl %%ebp\n\t"	/* gcc bug */ )
		: "=a" ( rc ), "=D" ( discard_D ), "=S" ( discard_S ),
		  "=b" ( discard_b )
		: "D" ( imgheader->execaddr.segoff ),
		  "S" ( imgheader->location ),
		  "b" ( __from_data16 ( basemem_packet ) )
		: "ecx", "edx" );

	return rc;
}

/**
 * Boot a 32-bit NBI image
 *
 * @v imgheader		Image header information
 * @ret rc		Return status code, if image returns
 */
static int nbi_boot32 ( struct image *image, struct imgheader *imgheader ) {
	struct ebinfo loaderinfo = {
		product_major_version, product_minor_version,
		0
	};
	int discard_D, discard_S, discard_b;
	int rc;

	DBGC ( image, "NBI %p executing 32-bit image at %lx\n",
	       image, imgheader->execaddr.linear );

	/* Jump to OS with flat physical addressing */
	__asm__ __volatile__ (
		PHYS_CODE ( "pushl %%ebp\n\t" /* gcc bug */
			    "pushl %%ebx\n\t" /* bootp data */
			    "pushl %%esi\n\t" /* imgheader */
			    "pushl %%eax\n\t" /* loaderinfo */
			    "call *%%edi\n\t"
			    "addl $12, %%esp\n\t" /* clean up stack */
			    "popl %%ebp\n\t" /* gcc bug */ )
		: "=a" ( rc ), "=D" ( discard_D ), "=S" ( discard_S ),
		  "=b" ( discard_b )
		: "D" ( imgheader->execaddr.linear ),
		  "S" ( ( imgheader->location.segment << 4 ) +
			imgheader->location.offset ),
		  "b" ( virt_to_phys ( basemem_packet ) ),
		  "a" ( virt_to_phys ( &loaderinfo ) )
		: "ecx", "edx", "memory" );

	return rc;
}

/**
 * Prepare DHCP parameter block for NBI image
 *
 * @v image		NBI image
 * @ret rc		Return status code
 */
static int nbi_prepare_dhcp ( struct image *image ) {
	struct net_device *boot_netdev;
	int rc;

	boot_netdev = last_opened_netdev();
	if ( ! boot_netdev ) {
		DBGC ( image, "NBI %p could not identify a network device\n",
		       image );
		return -ENODEV;
	}

	if ( ( rc = create_fakedhcpack ( boot_netdev, basemem_packet,
					 sizeof ( basemem_packet ) ) ) != 0 ) {
		DBGC ( image, "NBI %p failed to build DHCP packet\n", image );
		return rc;
	}

	return 0;
}

/**
 * Execute a loaded NBI image
 *
 * @v image		NBI image
 * @ret rc		Return status code
 */
static int nbi_exec ( struct image *image ) {
	struct imgheader imgheader;
	int may_return;
	int rc;

	/* Retrieve image header */
	copy_from_user ( &imgheader, image->data, 0, sizeof ( imgheader ) );

	DBGC ( image, "NBI %p placing header at %hx:%hx\n", image,
	       imgheader.location.segment, imgheader.location.offset );

	/* NBI files can have overlaps between segments; the bss of
	 * one segment may overlap the initialised data of another.  I
	 * assume this is a design flaw, but there are images out
	 * there that we need to work with.  We therefore do two
	 * passes: first to initialise the segments, then to copy the
	 * data.  This avoids zeroing out already-copied data.
	 */
	if ( ( rc = nbi_process_segments ( image, &imgheader,
					   nbi_prepare_segment ) ) != 0 )
		return rc;
	if ( ( rc = nbi_process_segments ( image, &imgheader,
					   nbi_load_segment ) ) != 0 )
		return rc;

	/* Prepare DHCP option block */
	if ( ( rc = nbi_prepare_dhcp ( image ) ) != 0 )
		return rc;

	/* Shut down now if NBI image will not return */
	may_return = NBI_PROGRAM_RETURNS ( imgheader.flags );
	if ( ! may_return )
		shutdown_boot();

	/* Execute NBI image */
	if ( NBI_LINEAR_EXEC_ADDR ( imgheader.flags ) ) {
		rc = nbi_boot32 ( image, &imgheader );
	} else {
	        rc = nbi_boot16 ( image, &imgheader );
	}

	if ( ! may_return ) {
		/* Cannot continue after shutdown() called */
		DBGC ( image, "NBI %p returned %d from non-returnable image\n",
		       image, rc  );
		while ( 1 ) {}
	}

	DBGC ( image, "NBI %p returned %d\n", image, rc );

	return rc;
}

/**
 * Probe NBI image
 *
 * @v image		NBI image
 * @ret rc		Return status code
 */
static int nbi_probe ( struct image *image ) {
	struct imgheader imgheader;

	/* If we don't have enough data give up */
	if ( image->len < NBI_HEADER_LENGTH ) {
		DBGC ( image, "NBI %p too short for an NBI image\n", image );
		return -ENOEXEC;
	}

	/* Check image header */
	copy_from_user ( &imgheader, image->data, 0, sizeof ( imgheader ) );
	if ( imgheader.magic != NBI_MAGIC ) {
		DBGC ( image, "NBI %p has no NBI signature\n", image );
		return -ENOEXEC;
	}

	return 0;
}

/** NBI image type */
struct image_type nbi_image_type __image_type ( PROBE_NORMAL ) = {
	.name = "NBI",
	.probe = nbi_probe,
	.exec = nbi_exec,
};
