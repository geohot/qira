/*
 * Constants etc. for the Bochs/Etherboot pseudo-NIC
 * 
 * This header file must be valid C and C++.
 *
 * Operation of the pseudo-NIC (PNIC) is pretty simple.  To write a
 * command plus data, first write the length of the data to
 * PNIC_REG_LEN, then write the data a byte at a type to
 * PNIC_REG_DATA, then write the command code to PNIC_REG_CMD.  The
 * status will be available from PNIC_REG_STAT.  The length of any
 * data returned will be in PNIC_REG_LEN and can be read a byte at a
 * time from PNIC_REG_DATA.
 */

FILE_LICENCE ( GPL2_OR_LATER );

/*
 * PCI parameters
 */
#define PNIC_PCI_VENDOR	0xfefe	/* Hopefully these won't clash with */
#define PNIC_PCI_DEVICE 0xefef	/* any real PCI device IDs.         */

/*
 * 'Hardware' register addresses, offset from io_base
 */
#define PNIC_REG_CMD	0x00	/* Command register, 2 bytes, write only */
#define PNIC_REG_STAT	0x00	/* Status register, 2 bytes, read only */
#define PNIC_REG_LEN	0x02	/* Length register, 2 bytes, read-write */
#define PNIC_REG_DATA	0x04	/* Data port, 1 byte, read-write */
/*
 * PNIC_MAX_REG used in Bochs to claim i/o space
 */
#define PNIC_MAX_REG	0x04

/*
 * Command code definitions: write these into PNIC_REG_CMD
 */
#define PNIC_CMD_NOOP		0x0000
#define PNIC_CMD_API_VER	0x0001
#define PNIC_CMD_READ_MAC	0x0002
#define PNIC_CMD_RESET		0x0003
#define PNIC_CMD_XMIT		0x0004
#define PNIC_CMD_RECV		0x0005
#define PNIC_CMD_RECV_QLEN	0x0006
#define PNIC_CMD_MASK_IRQ	0x0007
#define PNIC_CMD_FORCE_IRQ	0x0008

/*
 * Status code definitions: read these from PNIC_REG_STAT
 *
 * We avoid using status codes that might be confused with
 * randomly-read data (e.g. 0x0000, 0xffff etc.)
 */
#define PNIC_STATUS_OK		0x4f4b		/* 'OK' */
#define PNIC_STATUS_UNKNOWN_CMD	0x3f3f		/* '??' */

/*
 * Other miscellaneous information
 */

#define PNIC_API_VERSION	0x0101		/* 1.1 */
