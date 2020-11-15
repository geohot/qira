#ifndef _IPXE_FCOE_H
#define _IPXE_FCOE_H

/**
 * @file
 *
 * Fibre Channel over Ethernet
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/fc.h>
#include <ipxe/if_ether.h>

/** An FCoE name */
union fcoe_name {
	/** Fibre Channel name */
	struct fc_name fc;
	/** FCoE name */
	struct {
		/** Naming authority */
		uint16_t authority;
		/** MAC address */
		uint8_t mac[ETH_ALEN];
	} __attribute__ (( packed )) fcoe;
};

/** IEEE 48-bit address */
#define FCOE_AUTHORITY_IEEE 0x1000

/** IEEE extended */
#define FCOE_AUTHORITY_IEEE_EXTENDED 0x2000

/** An FCoE MAC address prefix (FC-MAP) */
struct fcoe_map {
	uint8_t bytes[3];
} __attribute__ (( packed ));

/** An FCoE (fabric-assigned) MAC address */
struct fcoe_mac {
	/** MAC address prefix */
	struct fcoe_map map;
	/** Port ID */
	struct fc_port_id port_id;
} __attribute__ (( packed ));

/** An FCoE header */
struct fcoe_header {
	/** FCoE frame version */
	uint8_t version;
	/** Reserved */
	uint8_t reserved[12];
	/** Start of Frame marker */
	uint8_t sof;
} __attribute__ (( packed ));

/** FCoE frame version */
#define FCOE_FRAME_VER 0x00

/** Start of Frame marker values */
enum fcoe_sof {
	FCOE_SOF_F = 0x28,	/**< Start of Frame Class F */
	FCOE_SOF_I2 = 0x2d,	/**< Start of Frame Initiate Class 2 */
	FCOE_SOF_N2 = 0x35,	/**< Start of Frame Normal Class 2 */
	FCOE_SOF_I3 = 0x2e,	/**< Start of Frame Initiate Class 3 */
	FCOE_SOF_N3 = 0x36,	/**< Start of Frame Normal Class 3 */
};

/** An FCoE footer */
struct fcoe_footer {
	/** CRC */
	uint32_t crc;
	/** End of frame marker */
	uint8_t eof;
	/** Reserved */
	uint8_t reserved[3];
} __attribute__ (( packed ));

/** End of Frame marker value */
enum fcoe_eof {
	FCOE_EOF_N = 0x41,	/**< End of Frame Normal */
	FCOE_EOF_T = 0x42,	/**< End of Frame Terminate */
	FCOE_EOF_NI = 0x49,	/**< End of Frame Invalid */
	FCOE_EOF_A = 0x50,	/**< End of Frame Abort */
};

/** FCoE VLAN priority */
#define FCOE_VLAN_PRIORITY 3

#endif /* _IPXE_FCOE_H */
