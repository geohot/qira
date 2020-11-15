/*
 * Copyright (C) 2006 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * Portions copyright (C) 2004 Anselm M. Hoffmeister
 * <stockholm@users.sourceforge.net>.
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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <byteswap.h>
#include <ipxe/refcnt.h>
#include <ipxe/iobuf.h>
#include <ipxe/xfer.h>
#include <ipxe/open.h>
#include <ipxe/resolv.h>
#include <ipxe/retry.h>
#include <ipxe/tcpip.h>
#include <ipxe/settings.h>
#include <ipxe/features.h>
#include <ipxe/dhcp.h>
#include <ipxe/dhcpv6.h>
#include <ipxe/dns.h>

/** @file
 *
 * DNS protocol
 *
 */

FEATURE ( FEATURE_PROTOCOL, "DNS", DHCP_EB_FEATURE_DNS, 1 );

/* Disambiguate the various error causes */
#define ENXIO_NO_RECORD __einfo_error ( EINFO_ENXIO_NO_RECORD )
#define EINFO_ENXIO_NO_RECORD \
	__einfo_uniqify ( EINFO_ENXIO, 0x01, "DNS name does not exist" )
#define ENXIO_NO_NAMESERVER __einfo_error ( EINFO_ENXIO_NO_NAMESERVER )
#define EINFO_ENXIO_NO_NAMESERVER \
	__einfo_uniqify ( EINFO_ENXIO, 0x02, "No DNS servers available" )

/** The DNS server */
static union {
	struct sockaddr sa;
	struct sockaddr_tcpip st;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
} nameserver = {
	.st = {
		.st_port = htons ( DNS_PORT ),
	},
};

/** The DNS search list */
static struct dns_name dns_search;

/**
 * Encode a DNS name using RFC1035 encoding
 *
 * @v string		DNS name as a string
 * @v name		DNS name to fill in
 * @ret len		Length of DNS name, or negative error
 */
int dns_encode ( const char *string, struct dns_name *name ) {
	uint8_t *start = ( name->data + name->offset );
	uint8_t *end = ( name->data + name->len );
	uint8_t *dst = start;
	size_t len = 0;
	char c;

	/* Encode name */
	while ( ( c = *(string++) ) ) {

		/* Handle '.' separators */
		if ( c == '.' ) {

			/* Reject consecutive '.' */
			if ( ( len == 0 ) && ( dst != start ) )
				return -EINVAL;

			/* Terminate if this is the trailing '.' */
			if ( *string == '\0' )
				break;

			/* Reject initial non-terminating '.' */
			if ( len == 0 )
				return -EINVAL;

			/* Reset length */
			len = 0;

		} else {

			/* Increment length */
			len++;

			/* Check for overflow */
			if ( len > DNS_MAX_LABEL_LEN )
				return -EINVAL;
		}

		/* Copy byte, update length */
		if ( ++dst < end ) {
			*dst = c;
			dst[-len] = len;
		}
	}

	/* Add terminating root marker */
	if ( len )
		dst++;
	if ( dst < end )
		*dst = '\0';
	dst++;

	return ( dst - start );
}

/**
 * Find start of valid label within an RFC1035-encoded DNS name
 *
 * @v name		DNS name
 * @v offset		Current offset
 * @ret offset		Offset of label, or negative error
 */
static int dns_label ( struct dns_name *name, size_t offset ) {
	const uint8_t *byte;
	const uint16_t *word;
	size_t len;
	size_t ptr;

	while ( 1 ) {

		/* Fail if we have overrun the DNS name */
		if ( ( offset + sizeof ( *byte) ) > name->len )
			return -EINVAL;
		byte = ( name->data + offset );

		/* Follow compression pointer, if applicable */
		if ( DNS_IS_COMPRESSED ( *byte ) ) {

			/* Fail if we have overrun the DNS name */
			if ( ( offset + sizeof ( *word ) ) > name->len )
				return -EINVAL;
			word = ( name->data + offset );

			/* Extract pointer to new offset */
			ptr = DNS_COMPRESSED_OFFSET ( ntohs ( *word ) );

			/* Fail if pointer does not point backwards.
			 * (This guarantees termination of the
			 * function.)
			 */
			if ( ptr >= offset )
				return -EINVAL;

			/* Continue from new offset */
			offset = ptr;
			continue;
		}

		/* Fail if we have overrun the DNS name */
		len = *byte;
		if ( ( offset + sizeof ( *byte ) + len ) > name->len )
			return -EINVAL;

		/* We have a valid label */
		return offset;
	}
}

/**
 * Decode RFC1035-encoded DNS name
 *
 * @v name		DNS name
 * @v data		Output buffer
 * @v len		Length of output buffer
 * @ret len		Length of decoded DNS name, or negative error
 */
int dns_decode ( struct dns_name *name, char *data, size_t len ) {
	unsigned int recursion_limit = name->len; /* Generous upper bound */
	int offset = name->offset;
	const uint8_t *label;
	size_t decoded_len = 0;
	size_t label_len;
	size_t copy_len;

	while ( recursion_limit-- ) {

		/* Find valid DNS label */
		offset = dns_label ( name, offset );
		if ( offset < 0 )
			return offset;

		/* Terminate if we have reached the root */
		label = ( name->data + offset );
		label_len = *(label++);
		if ( label_len == 0 ) {
			if ( decoded_len < len )
				*data = '\0';
			return decoded_len;
		}

		/* Prepend '.' if applicable */
		if ( decoded_len && ( decoded_len++ < len ) )
			*(data++) = '.';

		/* Copy label to output buffer */
		copy_len = ( ( decoded_len < len ) ? ( len - decoded_len ) : 0);
		if ( copy_len > label_len )
			copy_len = label_len;
		memcpy ( data, label, copy_len );
		data += copy_len;
		decoded_len += label_len;

		/* Move to next label */
		offset += ( sizeof ( *label ) + label_len );
	}

	/* Recursion limit exceeded */
	return -EINVAL;
}

/**
 * Compare DNS names for equality
 *
 * @v first		First DNS name
 * @v second		Second DNS name
 * @ret rc		Return status code
 */
int dns_compare ( struct dns_name *first, struct dns_name *second ) {
	unsigned int recursion_limit = first->len; /* Generous upper bound */
	int first_offset = first->offset;
	int second_offset = second->offset;
	const uint8_t *first_label;
	const uint8_t *second_label;
	size_t label_len;
	size_t len;

	while ( recursion_limit-- ) {

		/* Find valid DNS labels */
		first_offset = dns_label ( first, first_offset );
		if ( first_offset < 0 )
			return first_offset;
		second_offset = dns_label ( second, second_offset );
		if ( second_offset < 0 )
			return second_offset;

		/* Compare label lengths */
		first_label = ( first->data + first_offset );
		second_label = ( second->data + second_offset );
		label_len = *(first_label++);
		if ( label_len != *(second_label++) )
			return -ENOENT;
		len = ( sizeof ( *first_label ) + label_len );

		/* Terminate if we have reached the root */
		if ( label_len == 0 )
			return 0;

		/* Compare label contents (case-insensitively) */
		while ( label_len-- ) {
			if ( tolower ( *(first_label++) ) !=
			     tolower ( *(second_label++) ) )
				return -ENOENT;
		}

		/* Move to next labels */
		first_offset += len;
		second_offset += len;
	}

	/* Recursion limit exceeded */
	return -EINVAL;
}

/**
 * Copy a DNS name
 *
 * @v src		Source DNS name
 * @v dst		Destination DNS name
 * @ret len		Length of copied DNS name, or negative error
 */
int dns_copy ( struct dns_name *src, struct dns_name *dst ) {
	unsigned int recursion_limit = src->len; /* Generous upper bound */
	int src_offset = src->offset;
	size_t dst_offset = dst->offset;
	const uint8_t *label;
	size_t label_len;
	size_t copy_len;
	size_t len;

	while ( recursion_limit-- ) {

		/* Find valid DNS label */
		src_offset = dns_label ( src, src_offset );
		if ( src_offset < 0 )
			return src_offset;

		/* Copy as an uncompressed label */
		label = ( src->data + src_offset );
		label_len = *label;
		len = ( sizeof ( *label ) + label_len );
		copy_len = ( ( dst_offset < dst->len ) ?
			     ( dst->len - dst_offset ) : 0 );
		if ( copy_len > len )
			copy_len = len;
		memcpy ( ( dst->data + dst_offset ), label, copy_len );
		src_offset += len;
		dst_offset += len;

		/* Terminate if we have reached the root */
		if ( label_len == 0 )
			return ( dst_offset - dst->offset );
	}

	/* Recursion limit exceeded */
	return -EINVAL;
}

/**
 * Skip RFC1035-encoded DNS name
 *
 * @v name		DNS name
 * @ret offset		Offset to next name, or negative error
 */
int dns_skip ( struct dns_name *name ) {
	unsigned int recursion_limit = name->len; /* Generous upper bound */
	int offset = name->offset;
	int prev_offset;
	const uint8_t *label;
	size_t label_len;

	while ( recursion_limit-- ) {

		/* Find valid DNS label */
		prev_offset = offset;
		offset = dns_label ( name, prev_offset );
		if ( offset < 0 )
			return offset;

		/* Terminate if we have reached a compression pointer */
		if ( offset != prev_offset )
			return ( prev_offset + sizeof ( uint16_t ) );

		/* Skip this label */
		label = ( name->data + offset );
		label_len = *label;
		offset += ( sizeof ( *label ) + label_len );

		/* Terminate if we have reached the root */
		if ( label_len == 0 )
			return offset;
	}

	/* Recursion limit exceeded */
	return -EINVAL;
}

/**
 * Skip RFC1035-encoded DNS name in search list
 *
 * @v name		DNS name
 * @ret offset		Offset to next non-empty name, or negative error
 */
static int dns_skip_search ( struct dns_name *name ) {
	int offset;

	/* Find next name */
	offset = dns_skip ( name );
	if ( offset < 0 )
		return offset;

	/* Skip over any subsequent empty names (e.g. due to padding
	 * bytes used in the NDP DNSSL option).
	 */
	while ( ( offset < ( ( int ) name->len ) ) &&
		( *( ( uint8_t * ) ( name->data + offset ) ) == 0 ) ) {
		offset++;
	}

	return offset;
}

/**
 * Transcribe DNS name (for debugging)
 *
 * @v name		DNS name
 * @ret string		Transcribed DNS name
 */
static const char * dns_name ( struct dns_name *name ) {
	static char buf[256];
	int len;

	len = dns_decode ( name, buf, sizeof ( buf ) );
	return ( ( len < 0 ) ? "<INVALID>" : buf );
}

/**
 * Name a DNS query type (for debugging)
 *
 * @v type		Query type (in network byte order)
 * @ret name		Type name
 */
static const char * dns_type ( uint16_t type ) {
	switch ( type ) {
	case htons ( DNS_TYPE_A ):	return "A";
	case htons ( DNS_TYPE_AAAA ):	return "AAAA";
	case htons ( DNS_TYPE_CNAME ):	return "CNAME";
	default:			return "<UNKNOWN>";
	}
}

/** A DNS request */
struct dns_request {
	/** Reference counter */
	struct refcnt refcnt;
	/** Name resolution interface */
	struct interface resolv;
	/** Data transfer interface */
	struct interface socket;
	/** Retry timer */
	struct retry_timer timer;

	/** Socket address to fill in with resolved address */
	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} address;
	/** Initial query type */
	uint16_t qtype;
	/** Buffer for current query */
	struct {
		/** Query header */
		struct dns_header query;
		/** Name buffer */
		char name[DNS_MAX_NAME_LEN];
		/** Space for question */
		struct dns_question padding;
	} __attribute__ (( packed )) buf;
	/** Current query name */
	struct dns_name name;
	/** Question within current query */
	struct dns_question *question;
	/** Length of current query */
	size_t len;
	/** Offset of search suffix within current query */
	size_t offset;
	/** Search list */
	struct dns_name search;
	/** Recursion counter */
	unsigned int recursion;
};

/**
 * Mark DNS request as complete
 *
 * @v dns		DNS request
 * @v rc		Return status code
 */
static void dns_done ( struct dns_request *dns, int rc ) {

	/* Stop the retry timer */
	stop_timer ( &dns->timer );

	/* Shut down interfaces */
	intf_shutdown ( &dns->socket, rc );
	intf_shutdown ( &dns->resolv, rc );
}

/**
 * Mark DNS request as resolved and complete
 *
 * @v dns		DNS request
 * @v rc		Return status code
 */
static void dns_resolved ( struct dns_request *dns ) {

	DBGC ( dns, "DNS %p found address %s\n",
	       dns, sock_ntoa ( &dns->address.sa ) );

	/* Return resolved address */
	resolv_done ( &dns->resolv, &dns->address.sa );

	/* Mark operation as complete */
	dns_done ( dns, 0 );
}

/**
 * Construct DNS question
 *
 * @v dns		DNS request
 * @ret rc		Return status code
 */
static int dns_question ( struct dns_request *dns ) {
	static struct dns_name search_root = {
		.data = "",
		.len = 1,
	};
	struct dns_name *search = &dns->search;
	int len;
	size_t offset;

	/* Use root suffix if search list is empty */
	if ( search->offset == search->len )
		search = &search_root;

	/* Overwrite current suffix */
	dns->name.offset = dns->offset;
	len = dns_copy ( search, &dns->name );
	if ( len < 0 )
		return len;

	/* Sanity check */
	offset = ( dns->name.offset + len );
	if ( offset > dns->name.len ) {
		DBGC ( dns, "DNS %p name is too long\n", dns );
		return -EINVAL;
	}

	/* Construct question */
	dns->question = ( ( ( void * ) &dns->buf ) + offset );
	dns->question->qtype = dns->qtype;
	dns->question->qclass = htons ( DNS_CLASS_IN );

	/* Store length */
	dns->len = ( offset + sizeof ( *(dns->question) ) );

	/* Restore name */
	dns->name.offset = offsetof ( typeof ( dns->buf ), name );

	DBGC2 ( dns, "DNS %p question is %s type %s\n", dns,
		dns_name ( &dns->name ), dns_type ( dns->question->qtype ) );

	return 0;
}

/**
 * Send DNS query
 *
 * @v dns		DNS request
 * @ret rc		Return status code
 */
static int dns_send_packet ( struct dns_request *dns ) {
	struct dns_header *query = &dns->buf.query;

	/* Start retransmission timer */
	start_timer ( &dns->timer );

	/* Generate query identifier */
	query->id = random();

	/* Send query */
	DBGC ( dns, "DNS %p sending query ID %#04x for %s type %s\n", dns,
	       ntohs ( query->id ), dns_name ( &dns->name ),
	       dns_type ( dns->question->qtype ) );

	/* Send the data */
	return xfer_deliver_raw ( &dns->socket, query, dns->len );
}

/**
 * Handle DNS retransmission timer expiry
 *
 * @v timer		Retry timer
 * @v fail		Failure indicator
 */
static void dns_timer_expired ( struct retry_timer *timer, int fail ) {
	struct dns_request *dns =
		container_of ( timer, struct dns_request, timer );

	if ( fail ) {
		dns_done ( dns, -ETIMEDOUT );
	} else {
		dns_send_packet ( dns );
	}
}

/**
 * Receive new data
 *
 * @v dns		DNS request
 * @v iobuf		I/O buffer
 * @v meta		Data transfer metadata
 * @ret rc		Return status code
 */
static int dns_xfer_deliver ( struct dns_request *dns,
			      struct io_buffer *iobuf,
			      struct xfer_metadata *meta __unused ) {
	struct dns_header *response = iobuf->data;
	struct dns_header *query = &dns->buf.query;
	unsigned int qtype = dns->question->qtype;
	struct dns_name buf;
	union dns_rr *rr;
	int offset;
	size_t answer_offset;
	size_t next_offset;
	size_t rdlength;
	size_t name_len;
	int rc;

	/* Sanity check */
	if ( iob_len ( iobuf ) < sizeof ( *response ) ) {
		DBGC ( dns, "DNS %p received underlength packet length %zd\n",
		       dns, iob_len ( iobuf ) );
		rc = -EINVAL;
		goto done;
	}

	/* Check response ID matches query ID */
	if ( response->id != query->id ) {
		DBGC ( dns, "DNS %p received unexpected response ID %#04x "
		       "(wanted %d)\n", dns, ntohs ( response->id ),
		       ntohs ( query->id ) );
		rc = -EINVAL;
		goto done;
	}
	DBGC ( dns, "DNS %p received response ID %#04x\n",
	       dns, ntohs ( response->id ) );

	/* Check that we have exactly one question */
	if ( response->qdcount != htons ( 1 ) ) {
		DBGC ( dns, "DNS %p received response with %d questions\n",
		       dns, ntohs ( response->qdcount ) );
		rc = -EINVAL;
		goto done;
	}

	/* Skip question section */
	buf.data = iobuf->data;
	buf.offset = sizeof ( *response );
	buf.len = iob_len ( iobuf );
	offset = dns_skip ( &buf );
	if ( offset < 0 ) {
		rc = offset;
		DBGC ( dns, "DNS %p received response with malformed "
		       "question: %s\n", dns, strerror ( rc ) );
		goto done;
	}
	answer_offset = ( offset + sizeof ( struct dns_question ) );

	/* Search through response for useful answers.  Do this
	 * multiple times, to take advantage of useful nameservers
	 * which send us e.g. the CNAME *and* the A record for the
	 * pointed-to name.
	 */
	for ( buf.offset = answer_offset ; buf.offset != buf.len ;
	      buf.offset = next_offset ) {

		/* Check for valid name */
		offset = dns_skip ( &buf );
		if ( offset < 0 ) {
			rc = offset;
			DBGC ( dns, "DNS %p received response with malformed "
			       "answer: %s\n", dns, strerror ( rc ) );
			goto done;
		}

		/* Check for sufficient space for resource record */
		rr = ( buf.data + offset );
		if ( ( offset + sizeof ( rr->common ) ) > buf.len ) {
			DBGC ( dns, "DNS %p received response with underlength "
			       "RR\n", dns );
			rc = -EINVAL;
			goto done;
		}
		rdlength = ntohs ( rr->common.rdlength );
		next_offset = ( offset + sizeof ( rr->common ) + rdlength );
		if ( next_offset > buf.len ) {
			DBGC ( dns, "DNS %p received response with underlength "
			       "RR\n", dns );
			rc = -EINVAL;
			goto done;
		}

		/* Skip non-matching names */
		if ( dns_compare ( &buf, &dns->name ) != 0 ) {
			DBGC2 ( dns, "DNS %p ignoring response for %s type "
				"%s\n", dns, dns_name ( &buf ),
				dns_type ( rr->common.type ) );
			continue;
		}

		/* Handle answer */
		switch ( rr->common.type ) {

		case htons ( DNS_TYPE_AAAA ):

			/* Found the target AAAA record */
			if ( rdlength < sizeof ( dns->address.sin6.sin6_addr )){
				DBGC ( dns, "DNS %p received response with "
				       "underlength AAAA\n", dns );
				rc = -EINVAL;
				goto done;
			}
			dns->address.sin6.sin6_family = AF_INET6;
			memcpy ( &dns->address.sin6.sin6_addr,
				 &rr->aaaa.in6_addr,
				 sizeof ( dns->address.sin6.sin6_addr ) );
			dns_resolved ( dns );
			rc = 0;
			goto done;

		case htons ( DNS_TYPE_A ):

			/* Found the target A record */
			if ( rdlength < sizeof ( dns->address.sin.sin_addr ) ) {
				DBGC ( dns, "DNS %p received response with "
				       "underlength A\n", dns );
				rc = -EINVAL;
				goto done;
			}
			dns->address.sin.sin_family = AF_INET;
			dns->address.sin.sin_addr = rr->a.in_addr;
			dns_resolved ( dns );
			rc = 0;
			goto done;

		case htons ( DNS_TYPE_CNAME ):

			/* Terminate the operation if we recurse too far */
			if ( ++dns->recursion > DNS_MAX_CNAME_RECURSION ) {
				DBGC ( dns, "DNS %p recursion exceeded\n",
				       dns );
				rc = -ELOOP;
				dns_done ( dns, rc );
				goto done;
			}

			/* Found a CNAME record; update query and recurse */
			buf.offset = ( offset + sizeof ( rr->cname ) );
			DBGC ( dns, "DNS %p found CNAME %s\n",
			       dns, dns_name ( &buf ) );
			dns->search.offset = dns->search.len;
			name_len = dns_copy ( &buf, &dns->name );
			dns->offset = ( offsetof ( typeof ( dns->buf ), name ) +
					name_len - 1 /* Strip root label */ );
			if ( ( rc = dns_question ( dns ) ) != 0 ) {
				dns_done ( dns, rc );
				goto done;
			}
			next_offset = answer_offset;
			break;

		default:
			DBGC ( dns, "DNS %p got unknown record type %d\n",
			       dns, ntohs ( rr->common.type ) );
			break;
		}
	}

	/* Stop the retry timer.  After this point, each code path
	 * must either restart the timer by calling dns_send_packet(),
	 * or mark the DNS operation as complete by calling
	 * dns_done()
	 */
	stop_timer ( &dns->timer );

	/* Determine what to do next based on the type of query we
	 * issued and the response we received
	 */
	switch ( qtype ) {

	case htons ( DNS_TYPE_AAAA ):
		/* We asked for an AAAA record and got nothing; try
		 * the A.
		 */
		DBGC ( dns, "DNS %p found no AAAA record; trying A\n", dns );
		dns->question->qtype = htons ( DNS_TYPE_A );
		dns_send_packet ( dns );
		rc = 0;
		goto done;

	case htons ( DNS_TYPE_A ):
		/* We asked for an A record and got nothing;
		 * try the CNAME.
		 */
		DBGC ( dns, "DNS %p found no A record; trying CNAME\n", dns );
		dns->question->qtype = htons ( DNS_TYPE_CNAME );
		dns_send_packet ( dns );
		rc = 0;
		goto done;

	case htons ( DNS_TYPE_CNAME ):
		/* We asked for a CNAME record.  If we got a response
		 * (i.e. if the next AAAA/A query is already set up),
		 * then issue it.
		 */
		if ( qtype == dns->qtype ) {
			dns_send_packet ( dns );
			rc = 0;
			goto done;
		}

		/* If we have already reached the end of the search list,
		 * then terminate lookup.
		 */
		if ( dns->search.offset == dns->search.len ) {
			DBGC ( dns, "DNS %p found no CNAME record\n", dns );
			rc = -ENXIO_NO_RECORD;
			dns_done ( dns, rc );
			goto done;
		}

		/* Move to next entry in search list.  This can never fail,
		 * since we have already used this entry.
		 */
		DBGC ( dns, "DNS %p found no CNAME record; trying next "
		       "suffix\n", dns );
		dns->search.offset = dns_skip_search ( &dns->search );
		if ( ( rc = dns_question ( dns ) ) != 0 ) {
			dns_done ( dns, rc );
			goto done;
		}
		dns_send_packet ( dns );
		goto done;

	default:
		assert ( 0 );
		rc = -EINVAL;
		dns_done ( dns, rc );
		goto done;
	}

 done:
	/* Free I/O buffer */
	free_iob ( iobuf );
	return rc;
}

/**
 * Receive new data
 *
 * @v dns		DNS request
 * @v rc		Reason for close
 */
static void dns_xfer_close ( struct dns_request *dns, int rc ) {

	if ( ! rc )
		rc = -ECONNABORTED;

	dns_done ( dns, rc );
}

/** DNS socket interface operations */
static struct interface_operation dns_socket_operations[] = {
	INTF_OP ( xfer_deliver, struct dns_request *, dns_xfer_deliver ),
	INTF_OP ( intf_close, struct dns_request *, dns_xfer_close ),
};

/** DNS socket interface descriptor */
static struct interface_descriptor dns_socket_desc =
	INTF_DESC ( struct dns_request, socket, dns_socket_operations );

/** DNS resolver interface operations */
static struct interface_operation dns_resolv_op[] = {
	INTF_OP ( intf_close, struct dns_request *, dns_done ),
};

/** DNS resolver interface descriptor */
static struct interface_descriptor dns_resolv_desc =
	INTF_DESC ( struct dns_request, resolv, dns_resolv_op );

/**
 * Resolve name using DNS
 *
 * @v resolv		Name resolution interface
 * @v name		Name to resolve
 * @v sa		Socket address to fill in
 * @ret rc		Return status code
 */
static int dns_resolv ( struct interface *resolv,
			const char *name, struct sockaddr *sa ) {
	struct dns_request *dns;
	struct dns_header *query;
	size_t search_len;
	int name_len;
	int rc;

	/* Fail immediately if no DNS servers */
	if ( ! nameserver.sa.sa_family ) {
		DBG ( "DNS not attempting to resolve \"%s\": "
		      "no DNS servers\n", name );
		rc = -ENXIO_NO_NAMESERVER;
		goto err_no_nameserver;
	}

	/* Determine whether or not to use search list */
	search_len = ( strchr ( name, '.' ) ? 0 : dns_search.len );

	/* Allocate DNS structure */
	dns = zalloc ( sizeof ( *dns ) + search_len );
	if ( ! dns ) {
		rc = -ENOMEM;
		goto err_alloc_dns;
	}
	ref_init ( &dns->refcnt, NULL );
	intf_init ( &dns->resolv, &dns_resolv_desc, &dns->refcnt );
	intf_init ( &dns->socket, &dns_socket_desc, &dns->refcnt );
	timer_init ( &dns->timer, dns_timer_expired, &dns->refcnt );
	memcpy ( &dns->address.sa, sa, sizeof ( dns->address.sa ) );
	dns->search.data = ( ( ( void * ) dns ) + sizeof ( *dns ) );
	dns->search.len = search_len;
	memcpy ( dns->search.data, dns_search.data, search_len );

	/* Determine initial query type */
	switch ( nameserver.sa.sa_family ) {
	case AF_INET:
		dns->qtype = htons ( DNS_TYPE_A );
		break;
	case AF_INET6:
		dns->qtype = htons ( DNS_TYPE_AAAA );
		break;
	default:
		rc = -ENOTSUP;
		goto err_type;
	}

	/* Construct query */
	query = &dns->buf.query;
	query->flags = htons ( DNS_FLAG_RD );
	query->qdcount = htons ( 1 );
	dns->name.data = &dns->buf;
	dns->name.offset = offsetof ( typeof ( dns->buf ), name );
	dns->name.len = offsetof ( typeof ( dns->buf ), padding );
	name_len = dns_encode ( name, &dns->name );
	if ( name_len < 0 ) {
		rc = name_len;
		goto err_encode;
	}
	dns->offset = ( offsetof ( typeof ( dns->buf ), name ) +
			name_len - 1 /* Strip root label */ );
	if ( ( rc = dns_question ( dns ) ) != 0 )
		goto err_question;

	/* Open UDP connection */
	if ( ( rc = xfer_open_socket ( &dns->socket, SOCK_DGRAM,
				       &nameserver.sa, NULL ) ) != 0 ) {
		DBGC ( dns, "DNS %p could not open socket: %s\n",
		       dns, strerror ( rc ) );
		goto err_open_socket;
	}

	/* Start timer to trigger first packet */
	start_timer_nodelay ( &dns->timer );

	/* Attach parent interface, mortalise self, and return */
	intf_plug_plug ( &dns->resolv, resolv );
	ref_put ( &dns->refcnt );
	return 0;	

 err_open_socket:
 err_question:
 err_encode:
 err_type:
	ref_put ( &dns->refcnt );
 err_alloc_dns:
 err_no_nameserver:
	return rc;
}

/** DNS name resolver */
struct resolver dns_resolver __resolver ( RESOLV_NORMAL ) = {
	.name = "DNS",
	.resolv = dns_resolv,
};

/******************************************************************************
 *
 * Settings
 *
 ******************************************************************************
 */

/**
 * Format DNS search list setting
 *
 * @v type		Setting type
 * @v raw		Raw setting value
 * @v raw_len		Length of raw setting value
 * @v buf		Buffer to contain formatted value
 * @v len		Length of buffer
 * @ret len		Length of formatted value, or negative error
 */
static int format_dnssl_setting ( const struct setting_type *type __unused,
				  const void *raw, size_t raw_len,
				  char *buf, size_t len ) {
	struct dns_name name = {
		.data = ( ( void * ) raw ),
		.len = raw_len,
	};
	size_t remaining = len;
	size_t total = 0;
	int name_len;

	while ( name.offset < raw_len ) {

		/* Decode name */
		remaining = ( ( total < len ) ? ( len - total ) : 0 );
		name_len = dns_decode ( &name, ( buf + total ), remaining );
		if ( name_len < 0 )
			return name_len;
		total += name_len;

		/* Move to next name */
		name.offset = dns_skip_search ( &name );

		/* Add separator if applicable */
		if ( name.offset != raw_len ) {
			if ( total < len )
				buf[total] = ' ';
			total++;
		}
	}

	return total;
}

/** A DNS search list setting type */
const struct setting_type setting_type_dnssl __setting_type = {
	.name = "dnssl",
	.format = format_dnssl_setting,
};

/** IPv4 DNS server setting */
const struct setting dns_setting __setting ( SETTING_IP_EXTRA, dns ) = {
	.name = "dns",
	.description = "DNS server",
	.tag = DHCP_DNS_SERVERS,
	.type = &setting_type_ipv4,
};

/** IPv6 DNS server setting */
const struct setting dns6_setting __setting ( SETTING_IP_EXTRA, dns6 ) = {
	.name = "dns6",
	.description = "DNS server",
	.tag = DHCPV6_DNS_SERVERS,
	.type = &setting_type_ipv6,
	.scope = &ipv6_scope,
};

/** DNS search list */
const struct setting dnssl_setting __setting ( SETTING_IP_EXTRA, dnssl ) = {
	.name = "dnssl",
	.description = "DNS search list",
	.tag = DHCP_DOMAIN_SEARCH,
	.type = &setting_type_dnssl,
};

/**
 * Apply DNS search list
 *
 */
static void apply_dns_search ( void ) {
	char *localdomain;
	int len;

	/* Free existing search list */
	free ( dns_search.data );
	memset ( &dns_search, 0, sizeof ( dns_search ) );

	/* Fetch DNS search list */
	len = fetch_setting_copy ( NULL, &dnssl_setting, NULL, NULL,
				   &dns_search.data );
	if ( len >= 0 ) {
		dns_search.len = len;
		return;
	}

	/* If no DNS search list exists, try to fetch the local domain */
	fetch_string_setting_copy ( NULL, &domain_setting, &localdomain );
	if ( localdomain ) {
		len = dns_encode ( localdomain, &dns_search );
		if ( len >= 0 ) {
			dns_search.data = malloc ( len );
			if ( dns_search.data ) {
				dns_search.len = len;
				dns_encode ( localdomain, &dns_search );
			}
		}
		free ( localdomain );
		return;
	}
}

/**
 * Apply DNS settings
 *
 * @ret rc		Return status code
 */
static int apply_dns_settings ( void ) {

	/* Fetch DNS server address */
	nameserver.sa.sa_family = 0;
	if ( fetch_ipv6_setting ( NULL, &dns6_setting,
				  &nameserver.sin6.sin6_addr ) >= 0 ) {
		nameserver.sin6.sin6_family = AF_INET6;
	} else if ( fetch_ipv4_setting ( NULL, &dns_setting,
					 &nameserver.sin.sin_addr ) >= 0 ) {
		nameserver.sin.sin_family = AF_INET;
	}
	if ( nameserver.sa.sa_family ) {
		DBG ( "DNS using nameserver %s\n",
		      sock_ntoa ( &nameserver.sa ) );
	}

	/* Fetch DNS search list */
	apply_dns_search();
	if ( DBG_LOG && ( dns_search.len != 0 ) ) {
		struct dns_name name;
		int offset;

		DBG ( "DNS search list:" );
		memcpy ( &name, &dns_search, sizeof ( name ) );
		while ( name.offset != name.len ) {
			DBG ( " %s", dns_name ( &name ) );
			offset = dns_skip_search ( &name );
			if ( offset < 0 )
				break;
			name.offset = offset;
		}
		DBG ( "\n" );
	}

	return 0;
}

/** DNS settings applicator */
struct settings_applicator dns_applicator __settings_applicator = {
	.apply = apply_dns_settings,
};
