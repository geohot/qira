#ifndef _IPXE_PCCRR_H
#define _IPXE_PCCRR_H

/** @file
 *
 * Peer Content Caching and Retrieval: Retrieval Protocol [MS-PCCRR]
 *
 * All fields are in network byte order.
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/uaccess.h>

/** Magic retrieval URI path */
#define PEERDIST_MAGIC_PATH "/116B50EB-ECE2-41ac-8429-9F9E963361B7/"

/** Retrieval protocol version */
union peerdist_msg_version {
	/** Raw version number */
	uint32_t raw;
	/** Major:minor version number */
	struct {
		/** Minor version number */
		uint16_t minor;
		/** Major version number */
		uint16_t major;
	} __attribute__ (( packed ));
} __attribute__ (( packed ));

/** Retrieval protocol version 1.0 */
#define PEERDIST_MSG_VERSION_1_0 0x00000001UL

/** Retrieval protocol version 2.0 */
#define PEERDIST_MSG_VERSION_2_0 0x00000002UL

/** Retrieval protocol supported versions */
struct peerdist_msg_versions {
	/** Minimum supported protocol version */
	union peerdist_msg_version min;
	/** Maximum supported protocol version */
	union peerdist_msg_version max;
} __attribute__ (( packed ));

/** Retrieval protocol block range */
struct peerdist_msg_range {
	/** First block in range */
	uint32_t first;
	/** Number of blocks in range */
	uint32_t count;
} __attribute__ (( packed ));

/** Retrieval protocol segment ID header */
struct peerdist_msg_segment {
	/** Digest size (i.e. length of segment ID) */
	uint32_t digestsize;
	/* Followed by a single variable-length ID and padding:
	 *
	 * uint8_t id[digestsize];
	 * uint8_t pad[ (-digestsize) & 0x3 ];
	 */
} __attribute__ (( packed ));

/** Retrieval protocol segment ID
 *
 * @v digestsize	Digest size
 */
#define peerdist_msg_segment_t( digestsize )				\
	struct {							\
		struct peerdist_msg_segment segment;			\
		uint8_t id[digestsize];					\
		uint8_t pad[ ( -(digestsize) ) & 0x3 ];			\
	} __attribute__ (( packed ))

/** Retrieval protocol block range list header */
struct peerdist_msg_ranges {
	/** Number of ranges */
	uint32_t count;
	/* Followed by an array of block ranges:
	 *
	 * struct peerdist_msg_range range[count];
	 */
} __attribute__ (( packed ));

/** Retrieval protocol block range list
 *
 * @v count		Number of ranges
 */
#define peerdist_msg_ranges_t( count )					\
	struct {							\
		struct peerdist_msg_ranges ranges;			\
		struct peerdist_msg_range range[count];			\
	} __attribute__ (( packed ))

/** Retrieval protocol data block header */
struct peerdist_msg_block {
	/** Length of data block */
	uint32_t len;
	/* Followed by the (encrypted) data block:
	 *
	 * uint8_t data[len];
	 */
} __attribute__ (( packed ));

/** Retrieval protocol data block */
#define peerdist_msg_block_t( len )					\
	struct {							\
		struct peerdist_msg_block block;			\
		uint8_t data[len];					\
	} __attribute__ (( packed ))

/** Retrieval protocol initialisation vector header */
struct peerdist_msg_iv {
	/** Cipher block size */
	uint32_t blksize;
	/* Followed by the initialisation vector:
	 *
	 * uint8_t data[blksize];
	 */
} __attribute__ (( packed ));

/** Retrieval protocol initialisation vector */
#define peerdist_msg_iv_t( blksize )					\
	struct {							\
		struct peerdist_msg_iv iv;				\
		uint8_t data[blksize];					\
	} __attribute__ (( packed ))

/** Retrieval protocol useless VRF data header */
struct peerdist_msg_useless_vrf {
	/** Length of useless VRF data */
	uint32_t len;
	/* Followed by a variable-length useless VRF data block and
	 * padding:
	 *
	 * uint8_t data[len];
	 * uint8_t pad[ (-len) & 0x3 ];
	 */
} __attribute__ (( packed ));

/** Retrieval protocol useless VRF data */
#define peerdist_msg_useless_vrf_t( vrf_len )				\
	struct {							\
		struct peerdist_msg_useless_vrf vrf;			\
		uint8_t data[vrf_len];					\
		uint8_t pad[ ( -(vrf_len) ) & 0x3 ];			\
	} __attribute__ (( packed ))

/** Retrieval protocol message header */
struct peerdist_msg_header {
	/** Protocol version
	 *
	 * This is the protocol version in which the message type was
	 * first defined.
	 */
	union peerdist_msg_version version;
	/** Message type */
	uint32_t type;
	/** Message size (including this header) */
	uint32_t len;
	/** Cryptographic algorithm ID */
	uint32_t algorithm;
} __attribute__ (( packed ));

/** Retrieval protocol cryptographic algorithm IDs */
enum peerdist_msg_algorithm {
	/** No encryption */
	PEERDIST_MSG_PLAINTEXT = 0x00000000UL,
	/** AES-128 in CBC mode */
	PEERDIST_MSG_AES_128_CBC = 0x00000001UL,
	/** AES-192 in CBC mode */
	PEERDIST_MSG_AES_192_CBC = 0x00000002UL,
	/** AES-256 in CBC mode */
	PEERDIST_MSG_AES_256_CBC = 0x00000003UL,
};

/** Retrieval protocol transport response header */
struct peerdist_msg_transport_header {
	/** Length (excluding this header)
	 *
	 * This seems to be identical in both purpose and value to the
	 * length found within the message header, and therefore
	 * serves no useful purpose.
	 */
	uint32_t len;
} __attribute__ (( packed ));

/** Retrieval protocol negotiation request */
struct peerdist_msg_nego_req {
	/** Message header */
	struct peerdist_msg_header hdr;
	/** Supported versions */
	struct peerdist_msg_versions versions;
} __attribute__ (( packed ));

/** Retrieval protocol negotiation request version */
#define PEERDIST_MSG_NEGO_REQ_VERSION PEERDIST_MSG_VERSION_1_0

/** Retrieval protocol negotiation request type */
#define PEERDIST_MSG_NEGO_REQ_TYPE 0x00000000UL

/** Retrieval protocol negotiation response */
struct peerdist_msg_nego_resp {
	/** Message header */
	struct peerdist_msg_header hdr;
	/** Supported versions */
	struct peerdist_msg_versions versions;
} __attribute__ (( packed ));

/** Retrieval protocol negotiation response version */
#define PEERDIST_MSG_NEGO_RESP_VERSION PEERDIST_MSG_VERSION_1_0

/** Retrieval protocol negotiation response type */
#define PEERDIST_MSG_NEGO_RESP_TYPE 0x00000001UL

/** Retrieval protocol block list request header */
struct peerdist_msg_getblklist {
	/** Message header */
	struct peerdist_msg_header hdr;
	/* Followed by a segment ID and a block range list:
	 *
	 * peerdist_msg_segment_t(digestsize) segment;
	 * peerdist_msg_ranges_t(count) ranges;
	 */
} __attribute__ (( packed ));

/** Retrieval protocol block list request
 *
 * @v digestsize	Digest size
 * @v count		Block range count
 */
#define peerdist_msg_getblklist_t( digestsize, count )			\
	struct {							\
		struct peerdist_msg_getblklist getblklist;		\
		peerdist_msg_segment_t ( digestsize ) segment;		\
		peerdist_msg_ranges_t ( count ) ranges;			\
	} __attribute__ (( packed ))

/** Retrieval protocol block list request version */
#define PEERDIST_MSG_GETBLKLIST_VERSION PEERDIST_MSG_VERSION_1_0

/** Retrieval protocol block list request type */
#define PEERDIST_MSG_GETBLKLIST_TYPE 0x00000002UL

/** Retrieval protocol block fetch request header */
struct peerdist_msg_getblks {
	/** Message header */
	struct peerdist_msg_header hdr;
	/* Followed by a segment ID, a block range list, and a useless
	 * VRF block:
	 *
	 * peerdist_msg_segment_t(digestsize) segment;
	 * peerdist_msg_ranges_t(count) ranges;
	 * peerdist_msg_vrf_t(vrf_len) vrf;
	 */
} __attribute__ (( packed ));

/** Retrieval protocol block fetch request
 *
 * @v digestsize	Digest size
 * @v count		Block range count
 * @v vrf_len		Length of uselessness
 */
#define peerdist_msg_getblks_t( digestsize, count, vrf_len )		\
	struct {							\
		struct peerdist_msg_getblks getblks;			\
		peerdist_msg_segment_t ( digestsize ) segment;		\
		peerdist_msg_ranges_t ( count ) ranges;			\
		peerdist_msg_useless_vrf_t ( vrf_len );			\
	} __attribute__ (( packed ))

/** Retrieval protocol block fetch request version */
#define PEERDIST_MSG_GETBLKS_VERSION PEERDIST_MSG_VERSION_1_0

/** Retrieval protocol block fetch request type */
#define PEERDIST_MSG_GETBLKS_TYPE 0x00000003UL

/** Retrieval protocol block list response header */
struct peerdist_msg_blklist {
	/** Message header */
	struct peerdist_msg_header hdr;
	/* Followed by a segment ID, a block range list, and a next
	 * block index:
	 *
	 * peerdist_msg_segment_t(digestsize) segment;
	 * peerdist_msg_ranges_t(count) ranges;
	 * uint32_t next;
	 */
} __attribute__ (( packed ));

/** Retrieval protocol block list response
 *
 * @v digestsize	Digest size
 * @v count		Block range count
 */
#define peerdist_msg_blklist_t( digestsize, count )			\
	struct {							\
		struct peerdist_msg_blklist blklist;			\
		peerdist_msg_segment_t ( digestsize ) segment;		\
		peerdist_msg_ranges_t ( count ) ranges;			\
		uint32_t next;						\
	} __attribute__ (( packed ))

/** Retrieval protocol block list response version */
#define PEERDIST_MSG_BLKLIST_VERSION PEERDIST_MSG_VERSION_1_0

/** Retrieval protocol block list response type */
#define PEERDIST_MSG_BLKLIST_TYPE 0x00000004UL

/** Retrieval protocol block fetch response header */
struct peerdist_msg_blk {
	/** Message header */
	struct peerdist_msg_header hdr;
	/* Followed by a segment ID, a block index, a next block
	 * index, a data block, a useless VRF block, and an
	 * initialisation vector:
	 *
	 * peerdist_msg_segment_t(digestsize) segment;
	 * uint32_t index;
	 * uint32_t next;
	 * peerdist_msg_block_t(len) data;
	 * peerdist_msg_useless_vrf_t(vrf_len) vrf;
	 * peerdist_msg_iv_t(blksize) iv;
	 */
} __attribute__ (( packed ));

/** Retrieval protocol block fetch response
 *
 * @v digestsize	Digest size
 * @v len		Data block length
 * @v vrf_len		Length of uselessness
 * @v blksize		Cipher block size
 */
#define peerdist_msg_blk_t( digestsize, len, vrf_len, blksize )		\
	struct {							\
		struct peerdist_msg_blk blk;				\
		peerdist_msg_segment_t ( digestsize ) segment;		\
		uint32_t index;						\
		uint32_t next;						\
		peerdist_msg_block_t ( len ) block;			\
		peerdist_msg_useless_vrf_t ( vrf_len ) vrf;		\
		peerdist_msg_iv_t ( blksize ) iv;			\
	} __attribute__ (( packed ))

/** Retrieval protocol block fetch response version */
#define PEERDIST_MSG_BLK_VERSION PEERDIST_MSG_VERSION_1_0

/** Retrieval protocol block fetch response type */
#define PEERDIST_MSG_BLK_TYPE 0x00000005UL

/**
 * Parse retrieval protocol block fetch response
 *
 * @v raw		Raw data
 * @v raw_len		Length of raw data
 * @v digestsize	Digest size
 * @v blksize		Cipher block size
 * @v blk		Structure to fill in
 * @ret rc		Return status code
 */
#define peerdist_msg_blk( raw, raw_len, digestsize, blksize, blk ) ( {	\
	assert ( sizeof ( (blk)->segment.id ) == (digestsize) );	\
	assert ( sizeof ( (blk)->block.data ) == 0 );			\
	assert ( sizeof ( (blk)->vrf.data ) == 0 );			\
	assert ( sizeof ( (blk)->iv.data ) == blksize );		\
	peerdist_msg_blk_untyped ( (raw), (raw_len), (digestsize),	\
				   (blksize), blk );			\
	} )

extern int peerdist_msg_blk_untyped ( userptr_t raw, size_t raw_len,
				      size_t digestsize, size_t blksize,
				      void *out );

#endif /* _IPXE_PCCRR_H */
