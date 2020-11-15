#ifndef _IPXE_AOE_H
#define _IPXE_AOE_H

/** @file
 *
 * AoE protocol
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/list.h>
#include <ipxe/if_ether.h>
#include <ipxe/retry.h>
#include <ipxe/ata.h>
#include <ipxe/acpi.h>

/** An AoE config command */
struct aoecfg {
	/** AoE queue depth */
	uint16_t bufcnt;
	/** ATA target firmware version */
	uint16_t fwver;
	/** ATA target sector count */
	uint8_t scnt;
	/** AoE config string subcommand */
	uint8_t aoeccmd;
	/** AoE config string length */
	uint16_t cfglen;
	/** AoE config string */
	uint8_t data[0];
} __attribute__ (( packed ));

/** An AoE ATA command */
struct aoeata {
	/** AoE command flags */
	uint8_t aflags;
	/** ATA error/feature register */
	uint8_t err_feat;
	/** ATA sector count register */
	uint8_t count;
	/** ATA command/status register */
	uint8_t cmd_stat;
	/** Logical block address, in little-endian order */
	union {
		uint64_t u64;
		uint8_t bytes[6];
	} lba;
	/** Data payload */
	uint8_t data[0];
} __attribute__ (( packed ));

#define AOE_FL_EXTENDED	0x40	/**< LBA48 extended addressing */
#define AOE_FL_DEV_HEAD	0x10	/**< Device/head flag */
#define AOE_FL_ASYNC	0x02	/**< Asynchronous write */
#define AOE_FL_WRITE	0x01	/**< Write command */

/** An AoE command */
union aoecmd {
	/** Config command */
	struct aoecfg cfg;
	/** ATA command */
	struct aoeata ata;
};

/** An AoE header */
struct aoehdr {
	/** Protocol version number and flags */
	uint8_t ver_flags;
	/** Error code */
	uint8_t error;
	/** Major device number, in network byte order */
	uint16_t major;
	/** Minor device number */
	uint8_t minor;
	/** Command number */
	uint8_t command;
	/** Tag, in network byte order */
	uint32_t tag;
	/** Payload */
	union aoecmd payload[0];
} __attribute__ (( packed ));

#define AOE_VERSION	0x10	/**< Version 1 */
#define AOE_VERSION_MASK 0xf0	/**< Version part of ver_flags field */

#define AOE_FL_RESPONSE	0x08	/**< Message is a response */
#define AOE_FL_ERROR	0x04	/**< Command generated an error */

#define AOE_MAJOR_BROADCAST 0xffff
#define AOE_MINOR_BROADCAST 0xff

#define AOE_CMD_ATA	0x00	/**< Issue ATA command */
#define AOE_CMD_CONFIG	0x01	/**< Query Config Information */

#define AOE_ERR_BAD_COMMAND	1 /**< Unrecognised command code */
#define AOE_ERR_BAD_PARAMETER	2 /**< Bad argument parameter */
#define AOE_ERR_UNAVAILABLE	3 /**< Device unavailable */
#define AOE_ERR_CONFIG_EXISTS	4 /**< Config string present */
#define AOE_ERR_BAD_VERSION	5 /**< Unsupported version */

#define AOE_STATUS_ERR_MASK	0x0f /**< Error portion of status code */ 
#define AOE_STATUS_PENDING	0x80 /**< Command pending */

/** AoE tag magic marker */
#define AOE_TAG_MAGIC 0x18ae0000

/** Maximum number of sectors per packet */
#define AOE_MAX_COUNT 2

/** AoE boot firmware table signature */
#define ABFT_SIG ACPI_SIGNATURE ( 'a', 'B', 'F', 'T' )

/**
 * AoE Boot Firmware Table (aBFT)
 */
struct abft_table {
	/** ACPI header */
	struct acpi_description_header acpi;
	/** AoE shelf */
	uint16_t shelf;
	/** AoE slot */
	uint8_t slot;
	/** Reserved */
	uint8_t reserved_a;
	/** MAC address */
	uint8_t mac[ETH_ALEN];
} __attribute__ (( packed ));

#endif /* _IPXE_AOE_H */
