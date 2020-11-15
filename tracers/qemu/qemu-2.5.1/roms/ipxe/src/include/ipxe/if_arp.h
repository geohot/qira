#ifndef	_IPXE_IF_ARP_H
#define	_IPXE_IF_ARP_H

/** @file
 *
 * Address Resolution Protocol constants and types
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>

/* ARP protocol HARDWARE identifiers. */
#define ARPHRD_NETROM	0		/**< from KA9Q: NET/ROM pseudo	*/
#define ARPHRD_ETHER 	1		/**< Ethernet 10Mbps		*/
#define	ARPHRD_EETHER	2		/**< Experimental Ethernet	*/
#define	ARPHRD_AX25	3		/**< AX.25 Level 2		*/
#define	ARPHRD_PRONET	4		/**< PROnet token ring		*/
#define	ARPHRD_CHAOS	5		/**< Chaosnet			*/
#define	ARPHRD_IEEE802	6		/**< IEEE 802.2 Ethernet/TR/TB	*/
#define	ARPHRD_ARCNET	7		/**< ARCnet			*/
#define	ARPHRD_APPLETLK	8		/**< APPLEtalk			*/
#define ARPHRD_DLCI	15		/**< Frame Relay DLCI		*/
#define ARPHRD_ATM	19		/**< ATM 			*/
#define ARPHRD_METRICOM	23		/**< Metricom STRIP (new IANA id) */
#define	ARPHRD_IEEE1394	24		/**< IEEE 1394 IPv4 - RFC 2734	*/
#define ARPHRD_EUI64	27		/**< EUI-64			*/
#define ARPHRD_INFINIBAND 32		/**< InfiniBand			*/

/* ARP protocol opcodes. */
#define	ARPOP_REQUEST	1		/**< ARP request		*/
#define	ARPOP_REPLY	2		/**< ARP reply			*/
#define	ARPOP_RREQUEST	3		/**< RARP request		*/
#define	ARPOP_RREPLY	4		/**< RARP reply			*/
#define	ARPOP_InREQUEST	8		/**< InARP request		*/
#define	ARPOP_InREPLY	9		/**< InARP reply		*/
#define	ARPOP_NAK	10		/**< (ATM)ARP NAK		*/

/**
 * An ARP header
 *
 * This contains only the fixed-size portions of an ARP header; for
 * other fields use the arp_{sender,target}_{ha,pa} family of
 * functions.
 */
struct arphdr {
	/** Link-layer protocol
	 *
	 * This is an ARPHRD_XXX constant
	 */
	uint16_t ar_hrd;
	/** Network-layer protocol
	 *
	 * This is, for Ethernet, an ETH_P_XXX constant.
	 */
	uint16_t ar_pro;
	/** Link-layer address length */
	uint8_t ar_hln;
	/** Network-layer address length */
	uint8_t ar_pln;
	/** ARP opcode */
	uint16_t ar_op;
} __attribute__ (( packed ));

/** ARP packet sender hardware address
 *
 * @v arphdr	ARP header
 * @ret ar_sha	Sender hardware address
 */
static inline void * arp_sender_ha ( struct arphdr *arphdr ) {
	return ( ( ( void * ) arphdr ) + sizeof ( *arphdr ) );
}

/** ARP packet sender protocol address
 *
 * @v arphdr	ARP header
 * @ret ar_spa	Sender protocol address
 */
static inline void * arp_sender_pa ( struct arphdr *arphdr ) {
	return ( arp_sender_ha ( arphdr ) + arphdr->ar_hln );
}

/** ARP packet target hardware address
 *
 * @v arphdr	ARP header
 * @ret ar_tha	Target hardware address
 */
static inline void * arp_target_ha ( struct arphdr *arphdr ) {
	return ( arp_sender_pa ( arphdr ) + arphdr->ar_pln );
}

/** ARP packet target protocol address
 *
 * @v arphdr	ARP header
 * @ret ar_tpa	Target protocol address
 */
static inline void * arp_target_pa ( struct arphdr *arphdr ) {
	return ( arp_target_ha ( arphdr ) + arphdr->ar_hln );
}

#endif	/* _IPXE_IF_ARP_H */
