#ifndef _IPXE_DNS_H
#define _IPXE_DNS_H

/** @file
 *
 * DNS protocol
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/in.h>

/** DNS server port */
#define DNS_PORT 53

/** An RFC1035-encoded DNS name */
struct dns_name {
	/** Start of data */
	void *data;
	/** Offset of name within data */
	size_t offset;
	/** Total length of data */
	size_t len;
};

/**
 * Test for a DNS compression pointer
 *
 * @v byte		Initial byte
 * @ret is_compressed	Is a compression pointer
 */
#define DNS_IS_COMPRESSED( byte ) ( (byte) & 0xc0 )

/**
 * Extract DNS compression pointer
 *
 * @v word		Initial word
 * @ret offset		Offset
 */
#define DNS_COMPRESSED_OFFSET( word ) ( (word) & ~0xc000 )

/**
 * Extract DNS label length
 *
 * @v byte		Initial byte
 * @ret len		Label length
 */
#define DNS_LABEL_LEN( byte ) ( (byte) & ~0xc0 )

/** Maximum length of a single DNS label */
#define DNS_MAX_LABEL_LEN 0x3f

/** Maximum length of a DNS name (mandated by RFC1035 section 2.3.4) */
#define DNS_MAX_NAME_LEN 255

/** Maximum depth of CNAME recursion
 *
 * This is a policy decision.
 */
#define DNS_MAX_CNAME_RECURSION 32

/** A DNS packet header */
struct dns_header {
	/** Query identifier */
	uint16_t id;
	/** Flags */
	uint16_t flags;
	/** Number of question records */
	uint16_t qdcount;
	/** Number of answer records */
	uint16_t ancount;
	/** Number of name server records */
	uint16_t nscount;
	/** Number of additional records */
	uint16_t arcount;
} __attribute__ (( packed ));

/** Recursion desired flag */
#define DNS_FLAG_RD 0x0100

/** A DNS question */
struct dns_question {
	/** Query type */
	uint16_t qtype;
	/** Query class */
	uint16_t qclass;
} __attribute__ (( packed ));

/** DNS class "IN" */
#define DNS_CLASS_IN 1

/** A DNS resource record */
struct dns_rr_common {
	/** Type */
	uint16_t type;
	/** Class */
	uint16_t class;
	/** Time to live */
	uint32_t ttl;
	/** Resource data length */
	uint16_t rdlength;
} __attribute__ (( packed ));

/** Type of a DNS "A" record */
#define DNS_TYPE_A 1

/** A DNS "A" record */
struct dns_rr_a {
	/** Common fields */
	struct dns_rr_common common;
	/** IPv4 address */
	struct in_addr in_addr;
} __attribute__ (( packed ));

/** Type of a DNS "AAAA" record */
#define DNS_TYPE_AAAA 28

/** A DNS "AAAA" record */
struct dns_rr_aaaa {
	/** Common fields */
	struct dns_rr_common common;
	/** IPv6 address */
	struct in6_addr in6_addr;
} __attribute__ (( packed ));

/** Type of a DNS "NAME" record */
#define DNS_TYPE_CNAME 5

/** A DNS "CNAME" record */
struct dns_rr_cname {
	/** Common fields */
	struct dns_rr_common common;
} __attribute__ (( packed ));

/** A DNS resource record */
union dns_rr {
	/** Common fields */
	struct dns_rr_common common;
	/** "A" record */
	struct dns_rr_a a;
	/** "AAAA" record */
	struct dns_rr_aaaa aaaa;
	/** "CNAME" record */
	struct dns_rr_cname cname;
};

extern int dns_encode ( const char *string, struct dns_name *name );
extern int dns_decode ( struct dns_name *name, char *data, size_t len );
extern int dns_compare ( struct dns_name *first, struct dns_name *second );
extern int dns_copy ( struct dns_name *src, struct dns_name *dst );
extern int dns_skip ( struct dns_name *name );

#endif /* _IPXE_DNS_H */
