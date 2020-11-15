#ifndef _IPXE_EDD_H
#define _IPXE_EDD_H

/** @file
 *
 * Enhanced Disk Drive specification
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/interface.h>

/** An EDD host bus type */
struct edd_host_bus_type {
	/** Type */
	uint32_t type;
} __attribute__ (( packed ));

/** EDD bus type */
#define EDD_BUS_TYPE_FIXED( a, b, c, d, ... )				    \
	( ( (a) << 0 ) | ( (b) << 8 ) | ( (c) << 16 ) | ( (d) << 24 ) )
#define EDD_BUS_TYPE( ... )						    \
	EDD_BUS_TYPE_FIXED ( __VA_ARGS__, ' ', ' ', ' ', ' ' )
/** EDD PCI bus type */
#define EDD_BUS_TYPE_PCI EDD_BUS_TYPE ( 'P', 'C', 'I' )
/** EDD ISA bus type */
#define EDD_BUS_TYPE_ISA EDD_BUS_TYPE ( 'I', 'S', 'A' )
/** EDD PCI-X bus type */
#define EDD_BUS_TYPE_PCIX EDD_BUS_TYPE ( 'P', 'C', 'I', 'X' )
/** EDD Infiniband bus type */
#define EDD_BUS_TYPE_IBND EDD_BUS_TYPE ( 'I', 'B', 'N', 'D' )
/** EDD PCI Express bus type */
#define EDD_BUS_TYPE_XPRS EDD_BUS_TYPE ( 'X', 'P', 'R', 'S' )
/** EDD HyperTransport bus type */
#define EDD_BUS_TYPE_HTPT EDD_BUS_TYPE ( 'H', 'T', 'P', 'T' )

/** An EDD interface type */
struct edd_interface_type {
	/** Type */
	uint64_t type;
} __attribute__ (( packed ));

/** EDD interface type */
#define EDD_INTF_TYPE_FIXED( a, b, c, d, e, f, g, h, ... )		    \
	( ( ( ( uint64_t ) (a) ) <<  0 ) | ( ( ( uint64_t ) (b) ) <<  8 ) | \
	  ( ( ( uint64_t ) (c) ) << 16 ) | ( ( ( uint64_t ) (d) ) << 24 ) | \
	  ( ( ( uint64_t ) (e) ) << 32 ) | ( ( ( uint64_t ) (f) ) << 40 ) | \
	  ( ( ( uint64_t ) (g) ) << 48 ) | ( ( ( uint64_t ) (h) ) << 56 ) )
#define EDD_INTF_TYPE( ... )						    \
	EDD_INTF_TYPE_FIXED ( __VA_ARGS__,				    \
			      ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ' )
/** EDD ATA interface type */
#define EDD_INTF_TYPE_ATA EDD_INTF_TYPE ( 'A', 'T', 'A' )
/** EDD ATAPI interface type */
#define EDD_INTF_TYPE_ATAPI EDD_INTF_TYPE ( 'A', 'T', 'A', 'P', 'I' )
/** EDD SCSI interface type */
#define EDD_INTF_TYPE_SCSI EDD_INTF_TYPE ( 'S', 'C', 'S', 'I' )
/** EDD USB interface type */
#define EDD_INTF_TYPE_USB EDD_INTF_TYPE ( 'U', 'S', 'B' )
/** EDD 1394 interface type */
#define EDD_INTF_TYPE_1394 EDD_INTF_TYPE ( '1', '3', '9', '4' )
/** EDD Fibre Channel interface type */
#define EDD_INTF_TYPE_FIBRE EDD_INTF_TYPE ( 'F', 'I', 'B', 'R', 'E' )
/** EDD I2O interface type */
#define EDD_INTF_TYPE_I2O EDD_INTF_TYPE ( 'I', '2', 'O' )
/** EDD RAID interface type */
#define EDD_INTF_TYPE_RAID EDD_INTF_TYPE ( 'R', 'A', 'I', 'D' )
/** EDD SATA interface type */
#define EDD_INTF_TYPE_SATA EDD_INTF_TYPE ( 'S', 'A', 'T', 'A' )
/** EDD SAS interface type */
#define EDD_INTF_TYPE_SAS EDD_INTF_TYPE ( 'S', 'A', 'S' )

/** An EDD interface path */
union edd_interface_path {
	/** Legacy bus type */
	struct {
		/** Base address */
		uint16_t base;
	} __attribute__ (( packed )) legacy;
	/** PCI, PCI-X, PCI Express, or HyperTransport bus type */
	struct {
		/** Bus */
		uint8_t bus;
		/** Slot */
		uint8_t slot;
		/** Function */
		uint8_t function;
		/** Channel number */
		uint8_t channel;
	} __attribute__ (( packed )) pci;
	/** Padding */
	uint8_t pad[8];
} __attribute__ (( packed ));

/** An EDD device path */
union edd_device_path {
	/** ATA interface type */
	struct {
		/** Slave */
		uint8_t slave;
	} __attribute__ (( packed )) ata;
	/** ATAPI interface type */
	struct {
		/** Slave */
		uint8_t slave;
		/** Logical Unit Number */
		uint8_t lun;
	} __attribute__ (( packed )) atapi;
	/** SCSI interface type */
	struct {
		/** SCSI ID */
		uint16_t id;
		/** Logical Unit Number */
		uint64_t lun;
	} __attribute__ (( packed )) scsi;
	/** USB interface type */
	struct {
		/** Serial number */
		uint64_t serial;
	} __attribute__ (( packed )) usb;
	/** IEEE1394 interface type */
	struct {
		/** GUID */
		uint64_t guid;
	} __attribute__ (( packed )) ieee1394;
	/** Fibre Channel interface type */
	struct {
		/** WWN */
		uint64_t wwn;
		/** Logical Unit Number */
		uint64_t lun;
	} __attribute__ (( packed )) fibre;
	/** I2O interface type */
	struct {
		/** Identity tag */
		uint64_t tag;
	} __attribute__ (( packed )) i2o;
	/** RAID interface type */
	struct {
		/** Array number */
		uint32_t array;
	} __attribute__ (( packed )) raid;
	/** SATA interface type */
	struct {
		/** Port number */
		uint8_t port;
		/** Port multiplier number */
		uint8_t multiplier;
	} __attribute__ (( packed )) sata;
	/** SAS interface type */
	struct {
		/** Address */
		uint64_t address;
	} __attribute__ (( packed )) sas;
	/** Padding */
	uint8_t pad[16];
} __attribute__ (( packed ));

/** EDD device path information */
struct edd_device_path_information {
	/** Key */
	uint16_t key;
	/** Length of this structure */
	uint8_t len;
	/** Reserved */
	uint8_t reserved_a[3];
	/** Host bus type */
	struct edd_host_bus_type host_bus_type;
	/** Interface type */
	struct edd_interface_type interface_type;
	/** Interface path */
	union edd_interface_path interface_path;
	/** Device path */
	union edd_device_path device_path;
	/** Reserved */
	uint8_t reserved_b;
	/** Checksum */
	uint8_t checksum;
} __attribute__ (( packed ));

/** EDD device path information key */
#define EDD_DEVICE_PATH_INFO_KEY 0xbedd

extern int edd_describe ( struct interface *intf,
			  struct edd_interface_type *type,
			  union edd_device_path *path );
#define edd_describe_TYPE( object_type )				\
	typeof ( int ( object_type, struct edd_interface_type *type,	\
		       union edd_device_path *path ) )

#endif /* _IPXE_EDD_H */
