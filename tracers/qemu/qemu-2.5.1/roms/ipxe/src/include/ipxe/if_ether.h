#ifndef	_IPXE_IF_ETHER_H
#define	_IPXE_IF_ETHER_H

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>

#define ETH_ALEN		6	/* Size of Ethernet address */
#define ETH_HLEN		14	/* Size of ethernet header */
#define	ETH_ZLEN		60	/* Minimum packet */
#define	ETH_FRAME_LEN		1514	/* Maximum packet */
#define ETH_DATA_ALIGN		2	/* Amount needed to align the data after an ethernet header */
#ifndef	ETH_MAX_MTU
#define	ETH_MAX_MTU		(ETH_FRAME_LEN-ETH_HLEN)
#endif

#define ETH_P_RAW	0x0000	/* Raw packet */
#define ETH_P_IP	0x0800	/* Internet Protocl Packet */
#define ETH_P_ARP	0x0806	/* Address Resolution Protocol */
#define ETH_P_RARP	0x8035	/* Reverse Address resolution Protocol */
#define ETH_P_8021Q	0x8100	/* 802.1Q VLAN Extended Header */
#define ETH_P_IPV6	0x86DD	/* IPv6 over blueblook */
#define ETH_P_SLOW	0x8809	/* Ethernet slow protocols */
#define ETH_P_EAPOL	0x888E	/* 802.1X EAP over LANs */
#define ETH_P_AOE	0x88A2	/* ATA over Ethernet */
#define ETH_P_FCOE	0x8906	/* Fibre Channel over Ethernet */
#define ETH_P_FIP	0x8914	/* FCoE Initialization Protocol */

/** An Ethernet link-layer header */
struct ethhdr {
	/** Destination MAC address */
        uint8_t h_dest[ETH_ALEN];
	/** Source MAC address */
        uint8_t h_source[ETH_ALEN];
	/** Protocol ID */
        uint16_t h_protocol;
} __attribute__ ((packed));

#endif	/* _IPXE_IF_ETHER_H */
