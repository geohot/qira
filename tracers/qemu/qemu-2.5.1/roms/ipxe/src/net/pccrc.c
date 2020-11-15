/*
 * Copyright (C) 2015 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
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

#include <errno.h>
#include <assert.h>
#include <ipxe/uaccess.h>
#include <ipxe/sha256.h>
#include <ipxe/sha512.h>
#include <ipxe/hmac.h>
#include <ipxe/base16.h>
#include <ipxe/pccrc.h>

/** @file
 *
 * Peer Content Caching and Retrieval: Content Identification [MS-PCCRC]
 *
 */

/******************************************************************************
 *
 * Utility functions
 *
 ******************************************************************************
 */

/**
 * Transcribe hash value (for debugging)
 *
 * @v info		Content information
 * @v hash		Hash value
 * @ret string		Hash value string
 */
static inline const char *
peerdist_info_hash_ntoa ( const struct peerdist_info *info, const void *hash ) {
	static char buf[ ( 2 * PEERDIST_DIGEST_MAX_SIZE ) + 1 /* NUL */ ];
	size_t digestsize = info->digestsize;

	/* Sanity check */
	assert ( info != NULL );
	assert ( digestsize != 0 );
	assert ( base16_encoded_len ( digestsize ) < sizeof ( buf ) );

	/* Transcribe hash value */
	base16_encode ( hash, digestsize, buf, sizeof ( buf ) );
	return buf;
}

/**
 * Get raw data
 *
 * @v info		Content information
 * @v data		Data buffer
 * @v offset		Starting offset
 * @v len		Length
 * @ret rc		Return status code
 */
static int peerdist_info_get ( const struct peerdist_info *info, void *data,
			       size_t offset, size_t len ) {

	/* Sanity check */
	if ( ( offset > info->raw.len ) ||
	     ( len > ( info->raw.len - offset ) ) ) {
		DBGC ( info, "PCCRC %p data underrun at [%zx,%zx) of %zx\n",
		       info, offset, ( offset + len ), info->raw.len );
		return -ERANGE;
	}

	/* Copy data */
	copy_from_user ( data, info->raw.data, offset, len );

	return 0;
}

/**
 * Populate segment hashes
 *
 * @v segment		Content information segment to fill in
 * @v hash		Segment hash of data
 * @v secret		Segment secret
 */
static void peerdist_info_segment_hash ( struct peerdist_info_segment *segment,
					 const void *hash, const void *secret ){
	const struct peerdist_info *info = segment->info;
	struct digest_algorithm *digest = info->digest;
	uint8_t ctx[digest->ctxsize];
	size_t digestsize = info->digestsize;
	size_t secretsize = digestsize;
	static const uint16_t magic[] = PEERDIST_SEGMENT_ID_MAGIC;

	/* Sanity check */
	assert ( digestsize <= sizeof ( segment->hash ) );
	assert ( digestsize <= sizeof ( segment->secret ) );
	assert ( digestsize <= sizeof ( segment->id ) );

	/* Get segment hash of data */
	memcpy ( segment->hash, hash, digestsize );

	/* Get segment secret */
	memcpy ( segment->secret, secret, digestsize );

	/* Calculate segment identifier */
	hmac_init ( digest, ctx, segment->secret, &secretsize );
	assert ( secretsize == digestsize );
	hmac_update ( digest, ctx, segment->hash, digestsize );
	hmac_update ( digest, ctx, magic, sizeof ( magic ) );
	hmac_final ( digest, ctx, segment->secret, &secretsize, segment->id );
	assert ( secretsize == digestsize );
}

/******************************************************************************
 *
 * Content Information version 1
 *
 ******************************************************************************
 */

/**
 * Get number of blocks within a block description
 *
 * @v info		Content information
 * @v offset		Block description offset
 * @ret blocks		Number of blocks, or negative error
 */
static int peerdist_info_v1_blocks ( const struct peerdist_info *info,
				     size_t offset ) {
	struct peerdist_info_v1_block raw;
	unsigned int blocks;
	int rc;

	/* Get block description header */
	if ( ( rc = peerdist_info_get ( info, &raw, offset,
					sizeof ( raw ) ) ) != 0 )
		return rc;

	/* Calculate number of blocks */
	blocks = le32_to_cpu ( raw.blocks );

	return blocks;
}

/**
 * Locate block description
 *
 * @v info		Content information
 * @v index		Segment index
 * @ret offset		Block description offset, or negative error
 */
static ssize_t peerdist_info_v1_block_offset ( const struct peerdist_info *info,
					       unsigned int index ) {
	size_t digestsize = info->digestsize;
	unsigned int i;
	size_t offset;
	int blocks;
	int rc;

	/* Sanity check */
	assert ( index < info->segments );

	/* Calculate offset of first block description */
	offset = ( sizeof ( struct peerdist_info_v1 ) +
		   ( info->segments *
		     sizeof ( peerdist_info_v1_segment_t ( digestsize ) ) ) );

	/* Iterate over block descriptions until we find this segment */
	for ( i = 0 ; i < index ; i++ ) {

		/* Get number of blocks */
		blocks = peerdist_info_v1_blocks ( info, offset );
		if ( blocks < 0 ) {
			rc = blocks;
			DBGC ( info, "PCCRC %p segment %d could not get number "
			       "of blocks: %s\n", info, i, strerror ( rc ) );
			return rc;
		}

		/* Move to next block description */
		offset += sizeof ( peerdist_info_v1_block_t ( digestsize,
							      blocks ) );
	}

	return offset;
}

/**
 * Populate content information
 *
 * @v info		Content information to fill in
 * @ret rc		Return status code
 */
static int peerdist_info_v1 ( struct peerdist_info *info ) {
	struct peerdist_info_v1 raw;
	struct peerdist_info_segment first;
	struct peerdist_info_segment last;
	size_t first_skip;
	size_t last_skip;
	size_t last_read;
	int rc;

	/* Get raw header */
	if ( ( rc = peerdist_info_get ( info, &raw, 0, sizeof ( raw ) ) ) != 0){
		DBGC ( info, "PCCRC %p could not get V1 content information: "
		       "%s\n", info, strerror ( rc ) );
		return rc;
	}
	assert ( raw.version.raw == cpu_to_le16 ( PEERDIST_INFO_V1 ) );

	/* Determine hash algorithm */
	switch ( raw.hash ) {
	case cpu_to_le32 ( PEERDIST_INFO_V1_HASH_SHA256 ) :
		info->digest = &sha256_algorithm;
		break;
	case cpu_to_le32 ( PEERDIST_INFO_V1_HASH_SHA384 ) :
		info->digest = &sha384_algorithm;
		break;
	case cpu_to_le32 ( PEERDIST_INFO_V1_HASH_SHA512 ) :
		info->digest = &sha512_algorithm;
		break;
	default:
		DBGC ( info, "PCCRC %p unsupported hash algorithm %#08x\n",
		       info, le32_to_cpu ( raw.hash ) );
		return -ENOTSUP;
	}
	info->digestsize = info->digest->digestsize;
	assert ( info->digest != NULL );
	DBGC2 ( info, "PCCRC %p using %s[%zd]\n",
		info, info->digest->name, ( info->digestsize * 8 ) );

	/* Calculate number of segments */
	info->segments = le32_to_cpu ( raw.segments );

	/* Get first segment */
	if ( ( rc = peerdist_info_segment ( info, &first, 0 ) ) != 0 )
		return rc;

	/* Calculate range start offset */
	info->range.start = first.range.start;

	/* Calculate trimmed range start offset */
	first_skip = le32_to_cpu ( raw.first );
	info->trim.start = ( first.range.start + first_skip );

	/* Get last segment */
	if ( ( rc = peerdist_info_segment ( info, &last,
					    ( info->segments - 1 ) ) ) != 0 )
		return rc;

	/* Calculate range end offset */
	info->range.end = last.range.end;

	/* Calculate trimmed range end offset */
	if ( raw.last ) {
		/* Explicit length to include from last segment is given */
		last_read = le32_to_cpu ( raw.last );
		last_skip = ( last.index ? 0 : first_skip );
		info->trim.end = ( last.range.start + last_skip + last_read );
	} else {
		/* No explicit length given: range extends to end of segment */
		info->trim.end = last.range.end;
	}

	return 0;
}

/**
 * Populate content information segment
 *
 * @v segment		Content information segment to fill in
 * @ret rc		Return status code
 */
static int peerdist_info_v1_segment ( struct peerdist_info_segment *segment ) {
	const struct peerdist_info *info = segment->info;
	size_t digestsize = info->digestsize;
	peerdist_info_v1_segment_t ( digestsize ) raw;
	ssize_t raw_offset;
	int blocks;
	int rc;

	/* Sanity checks */
	assert ( segment->index < info->segments );

	/* Get raw description */
	raw_offset = ( sizeof ( struct peerdist_info_v1 ) +
		       ( segment->index * sizeof ( raw ) ) );
	if ( ( rc = peerdist_info_get ( info, &raw, raw_offset,
					sizeof ( raw ) ) ) != 0 ) {
		DBGC ( info, "PCCRC %p segment %d could not get segment "
		       "description: %s\n", info, segment->index,
		       strerror ( rc ) );
		return rc;
	}

	/* Calculate start offset of this segment */
	segment->range.start = le64_to_cpu ( raw.segment.offset );

	/* Calculate end offset of this segment */
	segment->range.end = ( segment->range.start +
			       le32_to_cpu ( raw.segment.len ) );

	/* Calculate block size of this segment */
	segment->blksize = le32_to_cpu ( raw.segment.blksize );

	/* Locate block description for this segment */
	raw_offset = peerdist_info_v1_block_offset ( info, segment->index );
	if ( raw_offset < 0 ) {
		rc = raw_offset;
		return rc;
	}

	/* Get number of blocks */
	blocks = peerdist_info_v1_blocks ( info, raw_offset );
	if ( blocks < 0 ) {
		rc = blocks;
		DBGC ( info, "PCCRC %p segment %d could not get number of "
		       "blocks: %s\n", info, segment->index, strerror ( rc ) );
		return rc;
	}
	segment->blocks = blocks;

	/* Calculate segment hashes */
	peerdist_info_segment_hash ( segment, raw.hash, raw.secret );

	return 0;
}

/**
 * Populate content information block
 *
 * @v block		Content information block to fill in
 * @ret rc		Return status code
 */
static int peerdist_info_v1_block ( struct peerdist_info_block *block ) {
	const struct peerdist_info_segment *segment = block->segment;
	const struct peerdist_info *info = segment->info;
	size_t digestsize = info->digestsize;
	peerdist_info_v1_block_t ( digestsize, segment->blocks ) raw;
	ssize_t raw_offset;
	int rc;

	/* Sanity checks */
	assert ( block->index < segment->blocks );

	/* Calculate start offset of this block */
	block->range.start = ( segment->range.start +
			       ( block->index * segment->blksize ) );

	/* Calculate end offset of this block */
	block->range.end = ( block->range.start + segment->blksize );
	if ( block->range.end > segment->range.end )
		block->range.end = segment->range.end;

	/* Locate block description */
	raw_offset = peerdist_info_v1_block_offset ( info, segment->index );
	if ( raw_offset < 0 ) {
		rc = raw_offset;
		return rc;
	}

	/* Get block hash */
	raw_offset += offsetof ( typeof ( raw ), hash[block->index] );
	if ( ( rc = peerdist_info_get ( info, block->hash, raw_offset,
					digestsize ) ) != 0 ) {
		DBGC ( info, "PCCRC %p segment %d block %d could not get "
		       "hash: %s\n", info, segment->index, block->index,
		       strerror ( rc ) );
		return rc;
	}

	return 0;
}

/** Content information version 1 operations */
static struct peerdist_info_operations peerdist_info_v1_operations = {
	.info = peerdist_info_v1,
	.segment = peerdist_info_v1_segment,
	.block = peerdist_info_v1_block,
};

/******************************************************************************
 *
 * Content Information version 2
 *
 ******************************************************************************
 */

/** A segment cursor */
struct peerdist_info_v2_cursor {
	/** Raw data offset */
	size_t offset;
	/** Number of segments remaining within this chunk */
	unsigned int remaining;
	/** Accumulated segment length */
	size_t len;
};

/**
 * Initialise segment cursor
 *
 * @v cursor		Segment cursor
 */
static inline void
peerdist_info_v2_cursor_init ( struct peerdist_info_v2_cursor *cursor ) {

	/* Initialise cursor */
	cursor->offset = ( sizeof ( struct peerdist_info_v2 ) +
			   sizeof ( struct peerdist_info_v2_chunk ) );
	cursor->remaining = 0;
	cursor->len = 0;
}

/**
 * Update segment cursor to next segment description
 *
 * @v info		Content information
 * @v offset		Current offset
 * @v remaining		Number of segments remaining within this chunk
 * @ret rc		Return status code
 */
static int
peerdist_info_v2_cursor_next ( const struct peerdist_info *info,
			       struct peerdist_info_v2_cursor *cursor ) {
	size_t digestsize = info->digestsize;
	peerdist_info_v2_segment_t ( digestsize ) raw;
	struct peerdist_info_v2_chunk chunk;
	int rc;

	/* Get chunk description if applicable */
	if ( ! cursor->remaining ) {

		/* Get chunk description */
		if ( ( rc = peerdist_info_get ( info, &chunk,
						( cursor->offset -
						  sizeof ( chunk ) ),
						sizeof ( chunk ) ) ) != 0 )
			return rc;

		/* Update number of segments remaining */
		cursor->remaining = ( be32_to_cpu ( chunk.len ) /
				      sizeof ( raw ) );
	}

	/* Get segment description header */
	if ( ( rc = peerdist_info_get ( info, &raw.segment, cursor->offset,
					sizeof ( raw.segment ) ) ) != 0 )
		return rc;

	/* Update cursor */
	cursor->offset += sizeof ( raw );
	cursor->remaining--;
	if ( ! cursor->remaining )
		cursor->offset += sizeof ( chunk );
	cursor->len += be32_to_cpu ( raw.segment.len );

	return 0;
}

/**
 * Get number of segments and total length
 *
 * @v info		Content information
 * @v len		Length to fill in
 * @ret rc		Number of segments, or negative error
 */
static int peerdist_info_v2_segments ( const struct peerdist_info *info,
				       size_t *len ) {
	struct peerdist_info_v2_cursor cursor;
	unsigned int segments;
	int rc;

	/* Iterate over all segments */
	for ( peerdist_info_v2_cursor_init ( &cursor ), segments = 0 ;
	      cursor.offset < info->raw.len ; segments++ ) {

		/* Update segment cursor */
		if ( ( rc = peerdist_info_v2_cursor_next ( info,
							   &cursor ) ) != 0 ) {
			DBGC ( info, "PCCRC %p segment %d could not update "
			       "segment cursor: %s\n",
			       info, segments, strerror ( rc ) );
			return rc;
		}
	}

	/* Record accumulated length */
	*len = cursor.len;

	return segments;
}

/**
 * Populate content information
 *
 * @v info		Content information to fill in
 * @ret rc		Return status code
 */
static int peerdist_info_v2 ( struct peerdist_info *info ) {
	struct peerdist_info_v2 raw;
	size_t len = 0;
	int segments;
	int rc;

	/* Get raw header */
	if ( ( rc = peerdist_info_get ( info, &raw, 0, sizeof ( raw ) ) ) != 0){
		DBGC ( info, "PCCRC %p could not get V2 content information: "
		       "%s\n", info, strerror ( rc ) );
		return rc;
	}
	assert ( raw.version.raw == cpu_to_le16 ( PEERDIST_INFO_V2 ) );

	/* Determine hash algorithm */
	switch ( raw.hash ) {
	case PEERDIST_INFO_V2_HASH_SHA512_TRUNC :
		info->digest = &sha512_algorithm;
		info->digestsize = ( 256 / 8 );
		break;
	default:
		DBGC ( info, "PCCRC %p unsupported hash algorithm %#02x\n",
		       info, raw.hash );
		return -ENOTSUP;
	}
	assert ( info->digest != NULL );
	DBGC2 ( info, "PCCRC %p using %s[%zd]\n",
		info, info->digest->name, ( info->digestsize * 8 ) );

	/* Calculate number of segments and total length */
	segments = peerdist_info_v2_segments ( info, &len );
	if ( segments < 0 ) {
		rc = segments;
		DBGC ( info, "PCCRC %p could not get segment count and length: "
		       "%s\n", info, strerror ( rc ) );
		return rc;
	}
	info->segments = segments;

	/* Calculate range start offset */
	info->range.start = be64_to_cpu ( raw.offset );

	/* Calculate trimmed range start offset */
	info->trim.start = ( info->range.start + be32_to_cpu ( raw.first ) );

	/* Calculate range end offset */
	info->range.end = ( info->range.start + len );

	/* Calculate trimmed range end offset */
	info->trim.end = ( raw.len ? be64_to_cpu ( raw.len ) :
			   info->range.end );

	return 0;
}

/**
 * Populate content information segment
 *
 * @v segment		Content information segment to fill in
 * @ret rc		Return status code
 */
static int peerdist_info_v2_segment ( struct peerdist_info_segment *segment ) {
	const struct peerdist_info *info = segment->info;
	size_t digestsize = info->digestsize;
	peerdist_info_v2_segment_t ( digestsize ) raw;
	struct peerdist_info_v2_cursor cursor;
	unsigned int index;
	size_t len;
	int rc;

	/* Sanity checks */
	assert ( segment->index < info->segments );

	/* Iterate over all segments before the target segment */
	for ( peerdist_info_v2_cursor_init ( &cursor ), index = 0 ;
	      index < segment->index ; index++ ) {

		/* Update segment cursor */
		if ( ( rc = peerdist_info_v2_cursor_next ( info,
							   &cursor ) ) != 0 ) {
			DBGC ( info, "PCCRC %p segment %d could not update "
			       "segment cursor: %s\n",
			       info, index, strerror ( rc ) );
			return rc;
		}
	}

	/* Get raw description */
	if ( ( rc = peerdist_info_get ( info, &raw, cursor.offset,
					sizeof ( raw ) ) ) != 0 ) {
		DBGC ( info, "PCCRC %p segment %d could not get segment "
		       "description: %s\n",
		       info, segment->index, strerror ( rc ) );
		return rc;
	}

	/* Calculate start offset of this segment */
	segment->range.start = ( info->range.start + cursor.len );

	/* Calculate end offset of this segment */
	len = be32_to_cpu ( raw.segment.len );
	segment->range.end = ( segment->range.start + len );

	/* Model as a segment containing a single block */
	segment->blocks = 1;
	segment->blksize = len;

	/* Calculate segment hashes */
	peerdist_info_segment_hash ( segment, raw.hash, raw.secret );

	return 0;
}

/**
 * Populate content information block
 *
 * @v block		Content information block to fill in
 * @ret rc		Return status code
 */
static int peerdist_info_v2_block ( struct peerdist_info_block *block ) {
	const struct peerdist_info_segment *segment = block->segment;
	const struct peerdist_info *info = segment->info;
	size_t digestsize = info->digestsize;

	/* Sanity checks */
	assert ( block->index < segment->blocks );

	/* Model as a block covering the whole segment */
	memcpy ( &block->range, &segment->range, sizeof ( block->range ) );
	memcpy ( block->hash, segment->hash, digestsize );

	return 0;
}

/** Content information version 2 operations */
static struct peerdist_info_operations peerdist_info_v2_operations = {
	.block = peerdist_info_v2_block,
	.segment = peerdist_info_v2_segment,
	.info = peerdist_info_v2,
};

/******************************************************************************
 *
 * Content Information
 *
 ******************************************************************************
 */

/**
 * Populate content information
 *
 * @v data		Raw data
 * @v len		Length of raw data
 * @v info		Content information to fill in
 * @ret rc		Return status code
 */
int peerdist_info ( userptr_t data, size_t len, struct peerdist_info *info ) {
	union peerdist_info_version version;
	int rc;

	/* Initialise structure */
	memset ( info, 0, sizeof ( *info ) );
	info->raw.data = data;
	info->raw.len = len;

	/* Get version */
	if ( ( rc = peerdist_info_get ( info, &version, 0,
					sizeof ( version ) ) ) != 0 ) {
		DBGC ( info, "PCCRC %p could not get version: %s\n",
		       info, strerror ( rc ) );
		return rc;
	}
	DBGC2 ( info, "PCCRC %p version %d.%d\n",
		info, version.major, version.minor );

	/* Determine version */
	switch ( version.raw ) {
	case cpu_to_le16 ( PEERDIST_INFO_V1 ) :
		info->op = &peerdist_info_v1_operations;
		break;
	case cpu_to_le16 ( PEERDIST_INFO_V2 ) :
		info->op = &peerdist_info_v2_operations;
		break;
	default:
		DBGC ( info, "PCCRC %p unsupported version %d.%d\n",
		       info, version.major, version.minor );
		return -ENOTSUP;
	}
	assert ( info->op != NULL );
	assert ( info->op->info != NULL );

	/* Populate content information */
	if ( ( rc = info->op->info ( info ) ) != 0 )
		return rc;

	DBGC2 ( info, "PCCRC %p range [%08zx,%08zx) covers [%08zx,%08zx) with "
		"%d segments\n", info, info->range.start, info->range.end,
		info->trim.start, info->trim.end, info->segments );
	return 0;
}

/**
 * Populate content information segment
 *
 * @v info		Content information
 * @v segment		Content information segment to fill in
 * @v index		Segment index
 * @ret rc		Return status code
 */
int peerdist_info_segment ( const struct peerdist_info *info,
			    struct peerdist_info_segment *segment,
			    unsigned int index ) {
	int rc;

	/* Sanity checks */
	assert ( info != NULL );
	assert ( info->op != NULL );
	assert ( info->op->segment != NULL );
	if ( index >= info->segments ) {
		DBGC ( info, "PCCRC %p segment %d of [0,%d) out of range\n",
		       info, index, info->segments );
		return -ERANGE;
	}

	/* Initialise structure */
	memset ( segment, 0, sizeof ( *segment ) );
	segment->info = info;
	segment->index = index;

	/* Populate content information segment */
	if ( ( rc = info->op->segment ( segment ) ) != 0 )
		return rc;

	DBGC2 ( info, "PCCRC %p segment %d range [%08zx,%08zx) with %d "
		"blocks\n", info, segment->index, segment->range.start,
		segment->range.end, segment->blocks );
	DBGC2 ( info, "PCCRC %p segment %d digest %s\n", info, segment->index,
		peerdist_info_hash_ntoa ( info, segment->hash ) );
	DBGC2 ( info, "PCCRC %p segment %d secret %s\n", info, segment->index,
		peerdist_info_hash_ntoa ( info, segment->secret ) );
	DBGC2 ( info, "PCCRC %p segment %d identf %s\n", info, segment->index,
		peerdist_info_hash_ntoa ( info, segment->id ) );
	return 0;
}

/**
 * Populate content information block
 *
 * @v segment		Content information segment
 * @v block		Content information block to fill in
 * @v index		Block index
 * @ret rc		Return status code
 */
int peerdist_info_block ( const struct peerdist_info_segment *segment,
			  struct peerdist_info_block *block,
			  unsigned int index ) {
	const struct peerdist_info *info = segment->info;
	size_t start;
	size_t end;
	int rc;

	/* Sanity checks */
	assert ( segment != NULL );
	assert ( info != NULL );
	assert ( info->op != NULL );
	assert ( info->op->block != NULL );
	if ( index >= segment->blocks ) {
		DBGC ( info, "PCCRC %p segment %d block %d of [0,%d) out of "
		       "range\n", info, segment->index, index, segment->blocks);
		return -ERANGE;
	}

	/* Initialise structure */
	memset ( block, 0, sizeof ( *block ) );
	block->segment = segment;
	block->index = index;

	/* Populate content information block */
	if ( ( rc = info->op->block ( block ) ) != 0 )
		return rc;

	/* Calculate trimmed range */
	start = block->range.start;
	if ( start < info->trim.start )
		start = info->trim.start;
	end = block->range.end;
	if ( end > info->trim.end )
		end = info->trim.end;
	if ( end < start )
		end = start;
	block->trim.start = start;
	block->trim.end = end;

	DBGC2 ( info, "PCCRC %p segment %d block %d hash %s\n",
		info, segment->index, block->index,
		peerdist_info_hash_ntoa ( info, block->hash ) );
	DBGC2 ( info, "PCCRC %p segment %d block %d range [%08zx,%08zx) covers "
		"[%08zx,%08zx)\n", info, segment->index, block->index,
		block->range.start, block->range.end, block->trim.start,
		block->trim.end );
	return 0;
}
