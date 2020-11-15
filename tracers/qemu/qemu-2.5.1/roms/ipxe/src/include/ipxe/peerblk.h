#ifndef _IPXE_PEERBLK_H
#define _IPXE_PEERBLK_H

/** @file
 *
 * Peer Content Caching and Retrieval (PeerDist) protocol block downloads
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/refcnt.h>
#include <ipxe/interface.h>
#include <ipxe/crypto.h>
#include <ipxe/aes.h>
#include <ipxe/xferbuf.h>
#include <ipxe/retry.h>
#include <ipxe/process.h>
#include <ipxe/pccrc.h>
#include <ipxe/peerdisc.h>

/** A PeerDist retrieval protocol decryption buffer descriptor */
struct peerdist_block_decrypt {
	/** Data transfer buffer */
	struct xfer_buffer *xferbuf;
	/** Offset within data transfer buffer */
	size_t offset;
	/** Length to use from data transfer buffer */
	size_t len;
};

/** PeerDist retrieval protocol decryption data transfer buffer indices */
enum peerdist_block_decrypt_index {
	/** Data before the trimmed content */
	PEERBLK_BEFORE = 0,
	/** Data within the trimmed content */
	PEERBLK_DURING,
	/** Data after the trimmed content */
	PEERBLK_AFTER,
	/** Number of decryption buffers */
	PEERBLK_NUM_BUFFERS
};

/** A PeerDist block download */
struct peerdist_block {
	/** Reference count */
	struct refcnt refcnt;
	/** Data transfer interface */
	struct interface xfer;
	/** Raw data interface */
	struct interface raw;
	/** Retrieval protocol interface */
	struct interface retrieval;

	/** Original URI */
	struct uri *uri;
	/** Content range of this block */
	struct peerdist_range range;
	/** Trimmed range of this block */
	struct peerdist_range trim;
	/** Offset of first byte in trimmed range within overall download */
	size_t offset;

	/** Digest algorithm */
	struct digest_algorithm *digest;
	/** Digest size
	 *
	 * Note that this may be shorter than the digest size of the
	 * digest algorithm.
	 */
	size_t digestsize;
	/** Digest context (statically allocated at instantiation time) */
	void *digestctx;

	/** Cipher algorithm */
	struct cipher_algorithm *cipher;
	/** Cipher context (dynamically allocated as needed) */
	void *cipherctx;

	/** Segment index */
	unsigned int segment;
	/** Segment identifier */
	uint8_t id[PEERDIST_DIGEST_MAX_SIZE];
	/** Segment secret */
	uint8_t secret[PEERDIST_DIGEST_MAX_SIZE];
	/** Block index */
	unsigned int block;
	/** Block hash */
	uint8_t hash[PEERDIST_DIGEST_MAX_SIZE];

	/** Current position (relative to incoming data stream) */
	size_t pos;
	/** Start of trimmed content (relative to incoming data stream) */
	size_t start;
	/** End of trimmed content (relative to incoming data stream) */
	size_t end;
	/** Data buffer */
	struct xfer_buffer buffer;

	/** Decryption process */
	struct process process;
	/** Decryption data buffer descriptors */
	struct peerdist_block_decrypt decrypt[PEERBLK_NUM_BUFFERS];
	/** Remaining decryption length */
	size_t cipher_remaining;
	/** Remaining digest length (excluding AES padding bytes) */
	size_t digest_remaining;

	/** Discovery client */
	struct peerdisc_client discovery;
	/** Current position in discovered peer list */
	struct peerdisc_peer *peer;
	/** Retry timer */
	struct retry_timer timer;
	/** Number of full attempt cycles completed */
	unsigned int cycles;
	/** Most recent attempt failure */
	int rc;

	/** Time at which block download was started */
	unsigned long started;
	/** Time at which most recent attempt was started */
	unsigned long attempted;
};

/** Retrieval protocol block fetch response (including transport header)
 *
 * @v digestsize	Digest size
 * @v len		Data block length
 * @v vrf_len		Length of uselessness
 * @v blksize		Cipher block size
 */
#define peerblk_msg_blk_t( digestsize, len, vrf_len, blksize )		\
	struct {							\
		struct peerdist_msg_transport_header hdr;		\
		peerdist_msg_blk_t ( digestsize, len, vrf_len,		\
				     blksize ) msg;			\
	} __attribute__ (( packed ))

extern int peerblk_open ( struct interface *xfer, struct uri *uri,
			  struct peerdist_info_block *block );

#endif /* _IPXE_PEERBLK_H */
