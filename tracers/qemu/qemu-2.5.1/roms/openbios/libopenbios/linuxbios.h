#ifndef LINUXBIOS_TABLES_H
#define LINUXBIOS_TABLES_H

/* The linuxbios table information is for conveying information
 * from the firmware to the loaded OS image.  Primarily this
 * is expected to be information that cannot be discovered by
 * other means, such as quering the hardware directly.
 *
 * All of the information should be Position Independent Data.
 * That is it should be safe to relocated any of the information
 * without it's meaning/correctnes changing.   For table that
 * can reasonably be used on multiple architectures the data
 * size should be fixed.  This should ease the transition between
 * 32 bit and 64 bit architectures etc.
 *
 * The completeness test for the information in this table is:
 * - Can all of the hardware be detected?
 * - Are the per motherboard constants available?
 * - Is there enough to allow a kernel to run that was written before
 *   a particular motherboard is constructed? (Assuming the kernel
 *   has drivers for all of the hardware but it does not have
 *   assumptions on how the hardware is connected together).
 *
 * With this test it should be straight forward to determine if a
 * table entry is required or not.  This should remove much of the
 * long term compatibility burden as table entries which are
 * irrelevant or have been replaced by better alternatives may be
 * dropped.  Of course it is polite and expidite to include extra
 * table entries and be backwards compatible, but it is not required.
 */


struct lb_header
{
	uint8_t  signature[4]; /* LBIO */
	uint32_t header_bytes;
	uint32_t header_checksum;
	uint32_t table_bytes;
	uint32_t table_checksum;
	uint32_t table_entries;
};

/* Every entry in the boot enviroment list will correspond to a boot
 * info record.  Encoding both type and size.  The type is obviously
 * so you can tell what it is.  The size allows you to skip that
 * boot enviroment record if you don't know what it easy.  This allows
 * forward compatibility with records not yet defined.
 */
struct lb_record {
	uint32_t tag;		/* tag ID */
	uint32_t size;		/* size of record (in bytes) */
};

#define LB_TAG_UNUSED	0x0000

#define LB_TAG_MEMORY	0x0001

struct lb_memory_range {
	uint64_t start;
	uint64_t size;
	uint32_t type;
#define LB_MEM_RAM       1	/* Memory anyone can use */
#define LB_MEM_RESERVED  2	/* Don't use this memory region */
#define LB_MEM_TABLE     16	/* Ram configuration tables are kept in */

};

struct lb_memory {
	uint32_t tag;
	uint32_t size;
	struct lb_memory_range map[0];
};

#define LB_TAG_HWRPB	0x0002
struct lb_hwrpb {
	uint32_t tag;
	uint32_t size;
	uint64_t hwrpb;
};

#define LB_TAG_MAINBOARD	0x0003
struct lb_mainboard {
	uint32_t tag;
	uint32_t size;
	uint8_t  vendor_idx;
	uint8_t  part_number_idx;
	uint8_t  strings[0];
};

#define LB_TAG_VERSION		0x0004
#define LB_TAG_EXTRA_VERSION	0x0005
#define LB_TAG_BUILD		0x0006
#define LB_TAG_COMPILE_TIME	0x0007
#define LB_TAG_COMPILE_BY	0x0008
#define LB_TAG_COMPILE_HOST	0x0009
#define LB_TAG_COMPILE_DOMAIN	0x000a
#define LB_TAG_COMPILER		0x000b
#define LB_TAG_LINKER		0x000c
#define LB_TAG_ASSEMBLER	0x000d
struct lb_string {
	uint32_t tag;
	uint32_t size;
	uint8_t  string[0];
};

/* The following structures are for the cmos definitions table */
#define LB_TAG_CMOS_OPTION_TABLE 200
/* cmos header record */
struct cmos_option_table {
	uint32_t tag;               /* CMOS definitions table type */
	uint32_t size;               /* size of the entire table */
	uint32_t header_length;      /* length of header */
};

/* cmos entry record
        This record is variable length.  The name field may be
        shorter than CMOS_MAX_NAME_LENGTH. The entry may start
        anywhere in the byte, but can not span bytes unless it
        starts at the beginning of the byte and the length is
        fills complete bytes.
*/
#define LB_TAG_OPTION 201
struct cmos_entries {
	uint32_t tag;                /* entry type */
	uint32_t size;               /* length of this record */
	uint32_t bit;                /* starting bit from start of image */
	uint32_t length;             /* length of field in bits */
	uint32_t config;             /* e=enumeration, h=hex, r=reserved */
	uint32_t config_id;          /* a number linking to an enumeration record */
#define CMOS_MAX_NAME_LENGTH 32
	uint8_t name[CMOS_MAX_NAME_LENGTH]; /* name of entry in ascii,
					       variable length int aligned */
};


/* cmos enumerations record
        This record is variable length.  The text field may be
        shorter than CMOS_MAX_TEXT_LENGTH.
*/
#define LB_TAG_OPTION_ENUM 202
struct cmos_enums {
	uint32_t tag;		     /* enumeration type */
	uint32_t size; 		     /* length of this record */
	uint32_t config_id;          /* a number identifying the config id */
	uint32_t value;              /* the value associated with the text */
#define CMOS_MAX_TEXT_LENGTH 32
	uint8_t text[CMOS_MAX_TEXT_LENGTH]; /* enum description in ascii,
						variable length int aligned */
};

/* cmos defaults record
        This record contains default settings for the cmos ram.
*/
#define LB_TAG_OPTION_DEFAULTS 203
struct cmos_defaults {
	uint32_t tag;                /* default type */
	uint32_t size;               /* length of this record */
	uint32_t name_length;        /* length of the following name field */
	uint8_t name[CMOS_MAX_NAME_LENGTH]; /* name identifying the default */
#define CMOS_IMAGE_BUFFER_SIZE 128
	uint8_t default_set[CMOS_IMAGE_BUFFER_SIZE]; /* default settings */
};

#define LB_TAG_OPTION_CHECKSUM 204
struct	cmos_checksum {
	uint32_t tag;
	uint32_t size;
	/* In practice everything is byte aligned, but things are measured
	 * in bits to be consistent.
	 */
	uint32_t range_start;	/* First bit that is checksummed (byte aligned) */
	uint32_t range_end;	/* Last bit that is checksummed (byte aligned) */
	uint32_t location;	/* First bit of the checksum (byte aligned) */
	uint32_t type;		/* Checksum algorithm that is used */
#define CHECKSUM_NONE	0
#define CHECKSUM_PCBIOS	1
};



#endif /* LINUXBIOS_TABLES_H */
