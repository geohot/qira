#ifndef _IPXE_SCSI_H
#define _IPXE_SCSI_H

#include <stdint.h>
#include <ipxe/uaccess.h>
#include <ipxe/interface.h>

/** @file
 *
 * SCSI devices
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/** Maximum block for READ/WRITE (10) commands */
#define SCSI_MAX_BLOCK_10 0xffffffffULL

/**
 * @defgroup scsiops SCSI operation codes
 * @{
 */

#define SCSI_OPCODE_READ_10		0x28	/**< READ (10) */
#define SCSI_OPCODE_READ_16		0x88	/**< READ (16) */
#define SCSI_OPCODE_WRITE_10		0x2a	/**< WRITE (10) */
#define SCSI_OPCODE_WRITE_16		0x8a	/**< WRITE (16) */
#define SCSI_OPCODE_READ_CAPACITY_10	0x25	/**< READ CAPACITY (10) */
#define SCSI_OPCODE_SERVICE_ACTION_IN	0x9e	/**< SERVICE ACTION IN */
#define SCSI_SERVICE_ACTION_READ_CAPACITY_16 0x10 /**< READ CAPACITY (16) */
#define SCSI_OPCODE_TEST_UNIT_READY	0x00	/**< TEST UNIT READY */

/** @} */

/**
 * @defgroup scsiflags SCSI flags
 * @{
 */

#define SCSI_FL_FUA_NV		0x02	/**< Force unit access to NVS */
#define SCSI_FL_FUA		0x08	/**< Force unit access */
#define SCSI_FL_DPO		0x10	/**< Disable cache page out */

/** @} */

/**
 * @defgroup scsicdbs SCSI command data blocks
 * @{
 */

/** A SCSI "READ (10)" CDB */
struct scsi_cdb_read_10 {
	/** Opcode (0x28) */
	uint8_t opcode;
	/** Flags */
	uint8_t flags;
	/** Start address
	 *
	 * This is a logical block number, in big-endian order.
	 */
	uint32_t lba;
	/** Group number */
	uint8_t group;
	/** Transfer length
	 *
	 * This is a logical block count, in big-endian order.
	 */
	uint16_t len;
	/** Control byte */
	uint8_t control;
} __attribute__ (( packed ));

/** A SCSI "READ (16)" CDB */
struct scsi_cdb_read_16 {
	/** Opcode (0x88) */
	uint8_t opcode;
	/** Flags */
	uint8_t flags;
	/** Start address
	 *
	 * This is a logical block number, in big-endian order.
	 */
	uint64_t lba;
	/** Transfer length
	 *
	 * This is a logical block count, in big-endian order.
	 */
	uint32_t len;
	/** Group number */
	uint8_t group;
	/** Control byte */
	uint8_t control;
} __attribute__ (( packed ));

/** A SCSI "WRITE (10)" CDB */
struct scsi_cdb_write_10 {
	/** Opcode (0x2a) */
	uint8_t opcode;
	/** Flags */
	uint8_t flags;
	/** Start address
	 *
	 * This is a logical block number, in big-endian order.
	 */
	uint32_t lba;
	/** Group number */
	uint8_t group;
	/** Transfer length
	 *
	 * This is a logical block count, in big-endian order.
	 */
	uint16_t len;
	/** Control byte */
	uint8_t control;
} __attribute__ (( packed ));

/** A SCSI "WRITE (16)" CDB */
struct scsi_cdb_write_16 {
	/** Opcode (0x8a) */
	uint8_t opcode;
	/** Flags */
	uint8_t flags;
	/** Start address
	 *
	 * This is a logical block number, in big-endian order.
	 */
	uint64_t lba;
	/** Transfer length
	 *
	 * This is a logical block count, in big-endian order.
	 */
	uint32_t len;
	/** Group number */
	uint8_t group;
	/** Control byte */
	uint8_t control;
} __attribute__ (( packed ));

/** A SCSI "READ CAPACITY (10)" CDB */
struct scsi_cdb_read_capacity_10 {
	/** Opcode (0x25) */
	uint8_t opcode;
	/** Reserved */
	uint8_t reserved_a;
	/** Logical block address
	 *
	 * Applicable only if the PMI bit is set.
	 */
	uint32_t lba;
	/** Reserved */
	uint8_t reserved_b[3];
	/** Control byte */
	uint8_t control;	
} __attribute__ (( packed ));

/** SCSI "READ CAPACITY (10)" parameter data */
struct scsi_capacity_10 {
	/** Maximum logical block number */
	uint32_t lba;
	/** Block length in bytes */
	uint32_t blksize;
} __attribute__ (( packed ));

/** A SCSI "READ CAPACITY (16)" CDB */
struct scsi_cdb_read_capacity_16 {
	/** Opcode (0x9e) */
	uint8_t opcode;
	/** Service action */
	uint8_t service_action;
	/** Logical block address
	 *
	 * Applicable only if the PMI bit is set.
	 */
	uint64_t lba;
	/** Transfer length
	 *
	 * This is the size of the data-in buffer, in bytes.
	 */
	uint32_t len;
	/** Reserved */
	uint8_t reserved;
	/** Control byte */
	uint8_t control;
} __attribute__ (( packed ));

/** SCSI "READ CAPACITY (16)" parameter data */
struct scsi_capacity_16 {
	/** Maximum logical block number */
	uint64_t lba;
	/** Block length in bytes */
	uint32_t blksize;
	/** Reserved */
	uint8_t reserved[20];
} __attribute__ (( packed ));

/** A SCSI "TEST UNIT READY" CDB */
struct scsi_cdb_test_unit_ready {
	/** Opcode (0x00) */
	uint8_t opcode;
	/** Reserved */
	uint8_t reserved[4];
	/** Control byte */
	uint8_t control;
} __attribute__ (( packed ));

/** A SCSI Command Data Block */
union scsi_cdb {
	struct scsi_cdb_read_10 read10;
	struct scsi_cdb_read_16 read16;
	struct scsi_cdb_write_10 write10;
	struct scsi_cdb_write_16 write16;
	struct scsi_cdb_read_capacity_10 readcap10;
	struct scsi_cdb_read_capacity_16 readcap16;
	struct scsi_cdb_test_unit_ready testready;
	unsigned char bytes[16];
};

/** printf() format for dumping a scsi_cdb */
#define SCSI_CDB_FORMAT "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:" \
			"%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x"

/** printf() parameters for dumping a scsi_cdb */
#define SCSI_CDB_DATA(cdb)						  \
	(cdb).bytes[0], (cdb).bytes[1], (cdb).bytes[2], (cdb).bytes[3],	  \
	(cdb).bytes[4], (cdb).bytes[5], (cdb).bytes[6], (cdb).bytes[7],	  \
	(cdb).bytes[8], (cdb).bytes[9], (cdb).bytes[10], (cdb).bytes[11], \
	(cdb).bytes[12], (cdb).bytes[13], (cdb).bytes[14], (cdb).bytes[15]

/** @} */

/** A SCSI LUN
 *
 * This is a four-level LUN as specified by SAM-2, in big-endian
 * order.
 */
struct scsi_lun {
	uint16_t u16[4];
}  __attribute__ (( packed ));

/** printf() format for dumping a scsi_lun */
#define SCSI_LUN_FORMAT "%04x-%04x-%04x-%04x"

/** printf() parameters for dumping a scsi_lun */
#define SCSI_LUN_DATA(lun)						  \
	ntohs ( (lun).u16[0] ), ntohs ( (lun).u16[1] ),			  \
	ntohs ( (lun).u16[2] ), ntohs ( (lun).u16[3] )

/** A SCSI command information unit */
struct scsi_cmd {
	/** LUN */
	struct scsi_lun lun;
	/** CDB for this command */
	union scsi_cdb cdb;
	/** Data-out buffer (may be NULL) */
	userptr_t data_out;
	/** Data-out buffer length
	 *
	 * Must be zero if @c data_out is NULL
	 */
	size_t data_out_len;
	/** Data-in buffer (may be NULL) */
	userptr_t data_in;
	/** Data-in buffer length
	 *
	 * Must be zero if @c data_in is NULL
	 */
	size_t data_in_len;
};

/** SCSI fixed-format sense data */
struct scsi_sns_fixed {
	/** Response code */
	uint8_t code;
	/** Reserved */
	uint8_t reserved;
	/** Sense key */
	uint8_t key;
	/** Information */
	uint32_t info;
	/** Additional sense length */
	uint8_t len;
	/** Command-specific information */
	uint32_t cs_info;
	/** Additional sense code and qualifier */
	uint16_t additional;
} __attribute__ (( packed ));

/** SCSI descriptor-format sense data */
struct scsi_sns_descriptor {
	/** Response code */
	uint8_t code;
	/** Sense key */
	uint8_t key;
	/** Additional sense code and qualifier */
	uint16_t additional;
} __attribute__ (( packed ));

/** SCSI sense data */
union scsi_sns {
	/** Response code */
	uint8_t code;
	/** Fixed-format sense data */
	struct scsi_sns_fixed fixed;
	/** Descriptor-format sense data */
	struct scsi_sns_descriptor desc;
};

/** SCSI sense response code mask */
#define SCSI_SENSE_CODE_MASK 0x7f

/** Test if SCSI sense data is in fixed format
 *
 * @v code		Response code
 * @ret is_fixed	Sense data is in fixed format
 */
#define SCSI_SENSE_FIXED( code ) ( ( (code) & 0x7e ) == 0x70 )

/** SCSI sense key mask */
#define SCSI_SENSE_KEY_MASK 0x0f

/** A SCSI response information unit */
struct scsi_rsp {
	/** SCSI status code */
	uint8_t status;
	/** Data overrun (or negative underrun) */
	ssize_t overrun;
	/** Autosense data (if any)
	 *
	 * To minimise code size, this is stored as the first four
	 * bytes of a descriptor-format sense data block (even if the
	 * response code indicates fixed-format sense data).
	 */
	struct scsi_sns_descriptor sense;
};

extern int scsi_parse_lun ( const char *lun_string, struct scsi_lun *lun );
extern void scsi_parse_sense ( const void *data, size_t len,
			       struct scsi_sns_descriptor *sense );

extern int scsi_command ( struct interface *control, struct interface *data,
			  struct scsi_cmd *command );
#define scsi_command_TYPE( object_type )				\
	typeof ( int ( object_type, struct interface *data,		\
		       struct scsi_cmd *command ) )

extern void scsi_response ( struct interface *intf, struct scsi_rsp *response );
#define scsi_response_TYPE( object_type ) \
	typeof ( void ( object_type, struct scsi_rsp *response ) )

extern int scsi_open ( struct interface *block, struct interface *scsi,
		       struct scsi_lun *lun );

#endif /* _IPXE_SCSI_H */
