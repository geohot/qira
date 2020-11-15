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

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <assert.h>
#include <ipxe/pccrd.h>

/** @file
 *
 * Peer Content Caching and Retrieval: Discovery Protocol [MS-PCCRD]
 *
 * This protocol manages to ingeniously combine the excessive
 * verbosity of XML with a paucity of actual information.  For
 * example: even in version 2.0 of the protocol it is still not
 * possible to discover which peers hold a specific block within a
 * given segment.
 *
 * For added bonus points, version 1.0 of the protocol is specified to
 * use a case-sensitive string comparison (for SHA2 digest values) but
 * nothing specifies whether the strings in question should be in
 * upper or lower case.  There are example strings given in the
 * specification, but the author skilfully manages to leave the issue
 * unresolved by using the somewhat implausible digest value of
 * "0200000000000000000000000000000000000000000000000000000000000000".
 *
 * Just in case you were thinking that the silver lining of the choice
 * to use an XML-based protocol would be the ability to generate and
 * process messages with standard tools, version 2.0 of the protocol
 * places most of the critical information inside a Base64-encoded
 * custom binary data structure.  Within an XML element, naturally.
 *
 * I hereby announce this specification to be the 2015 winner of the
 * prestigious "UEFI HII API" award for incompetent design.
 */

/** Discovery request format */
#define PEERDIST_DISCOVERY_REQUEST					      \
	"<?xml version=\"1.0\" encoding=\"utf-8\"?>"			      \
	"<soap:Envelope "						      \
	    "xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" "	      \
	    "xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" " \
	    "xmlns:wsd=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\" "  \
	    "xmlns:PeerDist=\"http://schemas.microsoft.com/p2p/"	      \
			     "2007/09/PeerDistributionDiscovery\">"	      \
	  "<soap:Header>"						      \
	    "<wsa:To>"							      \
	      "urn:schemas-xmlsoap-org:ws:2005:04:discovery"		      \
	    "</wsa:To>"							      \
	    "<wsa:Action>"						      \
	      "http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe"	      \
	    "</wsa:Action>"						      \
	    "<wsa:MessageID>"						      \
	      "urn:uuid:%s"						      \
	    "</wsa:MessageID>"						      \
	  "</soap:Header>"						      \
	  "<soap:Body>"							      \
	    "<wsd:Probe>"						      \
	      "<wsd:Types>"						      \
		"PeerDist:PeerDistData"					      \
	      "</wsd:Types>"						      \
	      "<wsd:Scopes MatchBy=\"http://schemas.xmlsoap.org/ws/"	      \
				    "2005/04/discovery/strcmp0\">"	      \
		"%s"							      \
	      "</wsd:Scopes>"						      \
	    "</wsd:Probe>"						      \
	  "</soap:Body>"						      \
	"</soap:Envelope>"

/**
 * Construct discovery request
 *
 * @v uuid		Message UUID string
 * @v id		Segment identifier string
 * @ret request		Discovery request, or NULL on failure
 *
 * The request is dynamically allocated; the caller must eventually
 * free() the request.
 */
char * peerdist_discovery_request ( const char *uuid, const char *id ) {
	char *request;
	int len;

	/* Construct request */
	len = asprintf ( &request, PEERDIST_DISCOVERY_REQUEST, uuid, id );
	if ( len < 0 )
		return NULL;

	return request;
}

/**
 * Locate discovery reply tag
 *
 * @v data		Reply data (not NUL-terminated)
 * @v len		Length of reply data
 * @v tag		XML tag
 * @ret found		Found tag (or NULL if not found)
 */
static char * peerdist_discovery_reply_tag ( char *data, size_t len,
					     const char *tag ) {
	size_t tag_len = strlen ( tag );

	/* Search, allowing for the fact that the reply data is not
	 * cleanly NUL-terminated and may contain embedded NULs due to
	 * earlier parsing.
	 */
	for ( ; len >= tag_len ; data++, len-- ) {
		if ( strncmp ( data, tag, tag_len ) == 0 )
			return data;
	}
	return NULL;
}

/**
 * Locate discovery reply values
 *
 * @v data		Reply data (not NUL-terminated, will be modified)
 * @v len		Length of reply data
 * @v name		XML tag name
 * @ret values		Tag values (or NULL if not found)
 *
 * The reply data is modified by adding NULs and moving characters as
 * needed to produce a NUL-separated list of values, terminated with a
 * zero-length string.
 *
 * This is not supposed to be a full XML parser; it's supposed to
 * include just enough functionality to allow PeerDist discovery to
 * work with existing implementations.
 */
static char * peerdist_discovery_reply_values ( char *data, size_t len,
						const char *name ) {
	char buf[ 2 /* "</" */ + strlen ( name ) + 1 /* ">" */ + 1 /* NUL */ ];
	char *open;
	char *close;
	char *start;
	char *end;
	char *in;
	char *out;
	char c;

	/* Locate opening tag */
	snprintf ( buf, sizeof ( buf ), "<%s>", name );
	open = peerdist_discovery_reply_tag ( data, len, buf );
	if ( ! open )
		return NULL;
	start = ( open + strlen ( buf ) );
	len -= ( start - data );
	data = start;

	/* Locate closing tag */
	snprintf ( buf, sizeof ( buf ), "</%s>", name );
	close = peerdist_discovery_reply_tag ( data, len, buf );
	if ( ! close )
		return NULL;
	assert ( close >= open );
	end = close;

	/* Strip initial whitespace, convert other whitespace
	 * sequences to single NULs, add terminating pair of NULs.
	 * This will probably overwrite part of the closing tag.
	 */
	for ( in = start, out = start ; in < end ; in++ ) {
		c = *in;
		if ( isspace ( c ) ) {
			if ( ( out > start ) && ( out[-1] != '\0' ) )
				*(out++) = '\0';
		} else {
			*(out++) = c;
		}
	}
	*(out++) = '\0';
	*(out++) = '\0';
	assert ( out < ( close + strlen ( buf ) ) );

	return start;
}

/**
 * Parse discovery reply
 *
 * @v data		Reply data (not NUL-terminated, will be modified)
 * @v len		Length of reply data
 * @v reply		Discovery reply to fill in
 * @ret rc		Return status code
 *
 * The discovery reply includes pointers to strings within the
 * modified reply data.
 */
int peerdist_discovery_reply ( char *data, size_t len,
			       struct peerdist_discovery_reply *reply ) {
	static const struct peerdist_discovery_block_count zcount = {
		.hex = "00000000",
	};
	struct peerdist_discovery_block_count *count;
	unsigned int max;
	unsigned int i;
	char *scopes;
	char *xaddrs;
	char *blockcount;
	char *in;
	char *out;
	size_t skip;

	/* Find <wsd:Scopes> tag */
	scopes = peerdist_discovery_reply_values ( data, len, "wsd:Scopes" );
	if ( ! scopes ) {
		DBGC ( reply, "PCCRD %p missing <wsd:Scopes> tag\n", reply );
		return -ENOENT;
	}

	/* Find <wsd:XAddrs> tag */
	xaddrs = peerdist_discovery_reply_values ( data, len, "wsd:XAddrs" );
	if ( ! xaddrs ) {
		DBGC ( reply, "PCCRD %p missing <wsd:XAddrs> tag\n", reply );
		return -ENOENT;
	}

	/* Find <PeerDist:BlockCount> tag */
	blockcount = peerdist_discovery_reply_values ( data, len,
						       "PeerDist:BlockCount" );
	if ( ! blockcount ) {
		DBGC ( reply, "PCCRD %p missing <PeerDist:BlockCount> tag\n",
		       reply );
		return -ENOENT;
	}

	/* Determine maximum number of segments (according to number
	 * of entries in the block count list).
	 */
	max = ( strlen ( blockcount ) / sizeof ( *count ) );
	count = container_of ( blockcount,
			       struct peerdist_discovery_block_count, hex[0] );

	/* Eliminate any segments with a zero block count */
	for ( i = 0, in = scopes, out = scopes ; *in ; i++, in += skip ) {

		/* Fail if we have overrun the maximum number of segments */
		if ( i >= max ) {
			DBGC ( reply, "PCCRD %p too many segment IDs\n",
			       reply );
			return -EPROTO;
		}

		/* Delete segment if block count is zero */
		skip = ( strlen ( in ) + 1 /* NUL */ );
		if ( memcmp ( count[i].hex, zcount.hex,
			      sizeof ( zcount.hex ) ) == 0 )
			continue;
		strcpy ( out, in );
		out += skip;
	}
	out[0] = '\0'; /* Ensure list is terminated with a zero-length string */

	/* Fill in discovery reply */
	reply->ids = scopes;
	reply->locations = xaddrs;

	return 0;
}
