#ifndef _IPXE_PCCRC_H
#define _IPXE_PCCRC_H

/** @file
 *
 * Peer Content Caching and Retrieval: Content Identification [MS-PCCRC]
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <byteswap.h>
#include <ipxe/uaccess.h>
#include <ipxe/crypto.h>

/******************************************************************************
 *
 * Content Information versioning
 *
 ******************************************************************************
 *
 * Note that version 1 data structures are little-endian, but version
 * 2 data structures are big-endian.
 */

/** Content Information version number */
union peerdist_info_version {
	/** Raw version number
	 *
	 * Always little-endian, regardless of whether the
	 * encompassing structure is version 1 (little-endian) or
	 * version 2 (big-endian).
	 */
	uint16_t raw;
	/** Major:minor version number */
	struct {
		/** Minor version number */
		uint8_t minor;
		/** Major version number */
		uint8_t major;
	} __attribute__ (( packed ));
} __attribute__ (( packed ));

/** Content Information version 1 */
#define PEERDIST_INFO_V1 0x0100

/** Content Information version 2 */
#define PEERDIST_INFO_V2 0x0200

/******************************************************************************
 *
 * Content Information version 1
 *
 ******************************************************************************
 */

/** Content Information version 1 data structure header
 *
 * All fields are little-endian.
 */
struct peerdist_info_v1 {
	/** Version number */
	union peerdist_info_version version;
	/** Hash algorithm
	 *
	 * This is a @c PEERDIST_INFO_V1_HASH_XXX constant.
	 */
	uint32_t hash;
	/** Length to skip in first segment
	 *
	 * Length at the start of the first segment which is not
	 * included within the content range.
	 */
	uint32_t first;
	/** Length to read in last segment, or zero
	 *
	 * Length within the last segment which is included within the
	 * content range.  A zero value indicates that the whole of
	 * the last segment is included within the content range.
	 */
	uint32_t last;
	/** Number of segments within the content information */
	uint32_t segments;
	/* Followed by a variable-length array of segment descriptions
	 * and a list of variable-length block descriptions:
	 *
	 * peerdist_info_v1_segment_t(digestsize) segment[segments];
	 * peerdist_info_v1_block_t(digestsize, block0.blocks) block0;
	 * peerdist_info_v1_block_t(digestsize, block1.blocks) block1;
	 * ...
	 * peerdist_info_v1_block_t(digestsize, blockN.blocks) blockN;
	 */
} __attribute__ (( packed ));

/** SHA-256 hash algorithm */
#define PEERDIST_INFO_V1_HASH_SHA256 0x0000800cUL

/** SHA-384 hash algorithm */
#define PEERDIST_INFO_V1_HASH_SHA384 0x0000800dUL

/** SHA-512 hash algorithm */
#define PEERDIST_INFO_V1_HASH_SHA512 0x0000800eUL

/** Content Information version 1 segment description header
 *
 * All fields are little-endian.
 */
struct peerdist_info_v1_segment {
	/** Offset of this segment within the content */
	uint64_t offset;
	/** Length of this segment
	 *
	 * Should always be 32MB, except for the last segment within
	 * the content.
	 */
	uint32_t len;
	/** Block size for this segment
	 *
	 * Should always be 64kB.  Note that the last block within the
	 * last segment may actually be less than 64kB.
	 */
	uint32_t blksize;
	/* Followed by two variable-length hashes:
	 *
	 * uint8_t hash[digestsize];
	 * uint8_t secret[digestsize];
	 *
	 * where digestsize is the digest size for the selected hash
	 * algorithm.
	 *
	 * Note that the hash is taken over (the hashes of all blocks
	 * within) the entire segment, even if the blocks do not
	 * intersect the content range (and so do not appear within
	 * the block list).  It therefore functions only as a segment
	 * identifier; it cannot be used to verify the content of the
	 * segment (since we may not download all blocks within the
	 * segment).
	 */
} __attribute__ (( packed ));

/** Content Information version 1 segment description
 *
 * @v digestsize	Digest size
 */
#define peerdist_info_v1_segment_t( digestsize )			\
	struct {							\
		struct peerdist_info_v1_segment segment;		\
		uint8_t hash[digestsize];				\
		uint8_t secret[digestsize];				\
	} __attribute__ (( packed ))

/** Content Information version 1 block description header
 *
 * All fields are little-endian.
 */
struct peerdist_info_v1_block {
	/** Number of blocks within the block description
	 *
	 * This is the number of blocks within the segment which
	 * overlap the content range.  It may therefore be less than
	 * the number of blocks within the segment.
	 */
	uint32_t blocks;
	/* Followed by an array of variable-length hashes:
	 *
	 * uint8_t hash[blocks][digestsize];
	 *
	 * where digestsize is the digest size for the selected hash
	 * algorithm.
	 */
 } __attribute__ (( packed ));

/** Content Information version 1 block description
 *
 * @v digestsize	Digest size
 * @v blocks		Number of blocks
 */
#define peerdist_info_v1_block_t( digestsize, blocks )			\
	struct {							\
		struct peerdist_info_v1_block block;			\
		uint8_t hash[blocks][digestsize];			\
	} __attribute__ (( packed ))

/******************************************************************************
 *
 * Content Information version 2
 *
 ******************************************************************************
 */

/** Content Information version 2 data structure header
 *
 * All fields are big-endian.
 */
struct peerdist_info_v2 {
	/** Version number */
	union peerdist_info_version version;
	/** Hash algorithm
	 *
	 * This is a @c PEERDIST_INFO_V2_HASH_XXX constant.
	 */
	uint8_t hash;
	/** Offset of the first segment within the content */
	uint64_t offset;
	/** Index of the first segment within the content */
	uint64_t index;
	/** Length to skip in first segment
	 *
	 * Length at the start of the first segment which is not
	 * included within the content range.
	 */
	uint32_t first;
	/** Length of content range, or zero
	 *
	 * Length of the content range.  A zero indicates that
	 * everything up to the end of the last segment is included in
	 * the content range.
	 */
	uint64_t len;
	/* Followed by a list of chunk descriptions */
} __attribute__ (( packed ));

/** SHA-512 hash algorithm with output truncated to first 256 bits */
#define PEERDIST_INFO_V2_HASH_SHA512_TRUNC 0x04

/** Content Information version 2 chunk description header
 *
 * All fields are big-endian.
 */
struct peerdist_info_v2_chunk {
	/** Chunk type */
	uint8_t type;
	/** Chunk data length */
	uint32_t len;
	/* Followed by an array of segment descriptions:
	 *
	 * peerdist_info_v2_segment_t(digestsize) segment[segments]
	 *
	 * where digestsize is the digest size for the selected hash
	 * algorithm, and segments is equal to @c len divided by the
	 * size of each segment array entry.
	 */
} __attribute__ (( packed ));

/** Content Information version 2 chunk description
 *
 * @v digestsize	Digest size
 */
#define peerdist_info_v2_chunk_t( digestsize )				\
	struct {							\
		struct peerdist_info_v2_chunk chunk;			\
		peerdist_info_v2_segment_t ( digestsize ) segment[0];	\
	} __attribute__ (( packed ))

/** Chunk type */
#define PEERDIST_INFO_V2_CHUNK_TYPE 0x00

/** Content Information version 2 segment description header
 *
 * All fields are big-endian.
 */
struct peerdist_info_v2_segment {
	/** Segment length */
	uint32_t len;
	/* Followed by two variable-length hashes:
	 *
	 * uint8_t hash[digestsize];
	 * uint8_t secret[digestsize];
	 *
	 * where digestsize is the digest size for the selected hash
	 * algorithm.
	 */
} __attribute__ (( packed ));

/** Content Information version 2 segment description
 *
 * @v digestsize	Digest size
 */
#define peerdist_info_v2_segment_t( digestsize )			\
	struct {							\
		struct peerdist_info_v2_segment segment;		\
		uint8_t hash[digestsize];				\
		uint8_t secret[digestsize];				\
	} __attribute__ (( packed ))

/******************************************************************************
 *
 * Content Information
 *
 ******************************************************************************
 */

/** Maximum digest size for any supported algorithm
 *
 * The largest digest size that we support is for SHA-512 at 64 bytes
 */
#define PEERDIST_DIGEST_MAX_SIZE 64

/** Raw content information */
struct peerdist_raw {
	/** Data buffer */
	userptr_t data;
	/** Length of data buffer */
	size_t len;
};

/** A content range */
struct peerdist_range {
	/** Start offset */
	size_t start;
	/** End offset */
	size_t end;
};

/** Content information */
struct peerdist_info {
	/** Raw content information */
	struct peerdist_raw raw;

	/** Content information operations */
	struct peerdist_info_operations *op;
	/** Digest algorithm */
	struct digest_algorithm *digest;
	/** Digest size
	 *
	 * Note that this may be shorter than the digest size of the
	 * digest algorithm.  The truncation does not always take
	 * place as soon as a digest is calculated.  For example,
	 * version 2 content information uses SHA-512 with a truncated
	 * digest size of 32 (256 bits), but the segment identifier
	 * ("HoHoDk") is calculated by using HMAC with the full
	 * SHA-512 digest and then truncating the HMAC output, rather
	 * than by simply using HMAC with the truncated SHA-512
	 * digest.  This is, of course, totally undocumented.
	 */
	size_t digestsize;
	/** Content range */
	struct peerdist_range range;
	/** Trimmed content range */
	struct peerdist_range trim;
	/** Number of segments within the content information */
	unsigned int segments;
};

/** A content information segment */
struct peerdist_info_segment {
	/** Content information */
	const struct peerdist_info *info;
	/** Segment index */
	unsigned int index;

	/** Content range
	 *
	 * Note that this range may exceed the overall content range.
	 */
	struct peerdist_range range;
	/** Number of blocks within this segment */
	unsigned int blocks;
	/** Block size */
	size_t blksize;
	/** Segment hash of data
	 *
	 * This is MS-PCCRC's "HoD".
	 */
	uint8_t hash[PEERDIST_DIGEST_MAX_SIZE];
	/** Segment secret
	 *
	 * This is MS-PCCRC's "Ke = Kp".
	 */
	uint8_t secret[PEERDIST_DIGEST_MAX_SIZE];
	/** Segment identifier
	 *
	 * This is MS-PCCRC's "HoHoDk".
	 */
	uint8_t id[PEERDIST_DIGEST_MAX_SIZE];
};

/** Magic string constant used to calculate segment identifier
 *
 * Note that the MS-PCCRC specification states that this constant is
 *
 *   "the null-terminated ASCII string constant "MS_P2P_CACHING";
 *    string literals are all ASCII strings with NULL terminators
 *    unless otherwise noted."
 *
 * The specification lies.  This constant is a UTF-16LE string, not an
 * ASCII string.  The terminating wNUL *is* included within the
 * constant.
 */
#define PEERDIST_SEGMENT_ID_MAGIC L"MS_P2P_CACHING"

/** A content information block */
struct peerdist_info_block {
	/** Content information segment */
	const struct peerdist_info_segment *segment;
	/** Block index */
	unsigned int index;

	/** Content range
	 *
	 * Note that this range may exceed the overall content range.
	 */
	struct peerdist_range range;
	/** Trimmed content range */
	struct peerdist_range trim;
	/** Block hash */
	uint8_t hash[PEERDIST_DIGEST_MAX_SIZE];
};

/** Content information operations */
struct peerdist_info_operations {
	/**
	 * Populate content information
	 *
	 * @v info		Content information to fill in
	 * @ret rc		Return status code
	 */
	int ( * info ) ( struct peerdist_info *info );
	/**
	 * Populate content information segment
	 *
	 * @v segment		Content information segment to fill in
	 * @ret rc		Return status code
	 */
	int ( * segment ) ( struct peerdist_info_segment *segment );
	/**
	 * Populate content information block
	 *
	 * @v block		Content information block to fill in
	 * @ret rc		Return status code
	 */
	int ( * block ) ( struct peerdist_info_block *block );
};

extern struct digest_algorithm sha512_trunc_algorithm;

extern int peerdist_info ( userptr_t data, size_t len,
			   struct peerdist_info *info );
extern int peerdist_info_segment ( const struct peerdist_info *info,
				   struct peerdist_info_segment *segment,
				   unsigned int index );
extern int peerdist_info_block ( const struct peerdist_info_segment *segment,
				 struct peerdist_info_block *block,
				 unsigned int index );

#endif /* _IPXE_PCCRC_H */
