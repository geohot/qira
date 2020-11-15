#ifndef PXE_H
#define PXE_H

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include "pxe_types.h"
#include "pxe_error.h"
#include "pxe_api.h"
#include <ipxe/device.h>
#include <ipxe/tables.h>

/** PXE API invalid function code */
#define PXENV_UNKNOWN 0xffff

/** Parameter block for pxenv_unknown() */
struct s_PXENV_UNKNOWN {
	PXENV_STATUS_t Status;			/**< PXE status code */
} __attribute__ (( packed ));

typedef struct s_PXENV_UNKNOWN PXENV_UNKNOWN_t;

/* Union used for PXE API calls; we don't know the type of the
 * structure until we interpret the opcode.  Also, Status is available
 * in the same location for any opcode, and it's convenient to have
 * non-specific access to it.
 */
union u_PXENV_ANY {
	/* Make it easy to read status for any operation */
	PXENV_STATUS_t				Status;
	struct s_PXENV_UNKNOWN			unknown;
	struct s_PXENV_UNLOAD_STACK		unload_stack;
	struct s_PXENV_GET_CACHED_INFO		get_cached_info;
	struct s_PXENV_TFTP_READ_FILE		restart_tftp;
	struct s_PXENV_START_UNDI		start_undi;
	struct s_PXENV_STOP_UNDI		stop_undi;
	struct s_PXENV_START_BASE		start_base;
	struct s_PXENV_STOP_BASE		stop_base;
	struct s_PXENV_TFTP_OPEN		tftp_open;
	struct s_PXENV_TFTP_CLOSE		tftp_close;
	struct s_PXENV_TFTP_READ		tftp_read;
	struct s_PXENV_TFTP_READ_FILE		tftp_read_file;
	struct s_PXENV_TFTP_GET_FSIZE		tftp_get_fsize;
	struct s_PXENV_UDP_OPEN			udp_open;
	struct s_PXENV_UDP_CLOSE		udp_close;
	struct s_PXENV_UDP_WRITE		udp_write;
	struct s_PXENV_UDP_READ			udp_read;
	struct s_PXENV_UNDI_STARTUP		undi_startup;
	struct s_PXENV_UNDI_CLEANUP		undi_cleanup;
	struct s_PXENV_UNDI_INITIALIZE		undi_initialize;
	struct s_PXENV_UNDI_RESET		undi_reset_adapter;
	struct s_PXENV_UNDI_SHUTDOWN		undi_shutdown;
	struct s_PXENV_UNDI_OPEN		undi_open;
	struct s_PXENV_UNDI_CLOSE		undi_close;
	struct s_PXENV_UNDI_TRANSMIT		undi_transmit;
	struct s_PXENV_UNDI_SET_MCAST_ADDRESS	undi_set_mcast_address;
	struct s_PXENV_UNDI_SET_STATION_ADDRESS undi_set_station_address;
	struct s_PXENV_UNDI_SET_PACKET_FILTER	undi_set_packet_filter;
	struct s_PXENV_UNDI_GET_INFORMATION	undi_get_information;
	struct s_PXENV_UNDI_GET_STATISTICS	undi_get_statistics;
	struct s_PXENV_UNDI_CLEAR_STATISTICS	undi_clear_statistics;
	struct s_PXENV_UNDI_INITIATE_DIAGS	undi_initiate_diags;
	struct s_PXENV_UNDI_FORCE_INTERRUPT	undi_force_interrupt;
	struct s_PXENV_UNDI_GET_MCAST_ADDRESS	undi_get_mcast_address;
	struct s_PXENV_UNDI_GET_NIC_TYPE	undi_get_nic_type;
	struct s_PXENV_UNDI_GET_IFACE_INFO	undi_get_iface_info;
	struct s_PXENV_UNDI_GET_STATE		undi_get_state;
	struct s_PXENV_UNDI_ISR			undi_isr;
	struct s_PXENV_FILE_OPEN		file_open;
	struct s_PXENV_FILE_CLOSE		file_close;
	struct s_PXENV_FILE_SELECT		file_select;
	struct s_PXENV_FILE_READ		file_read;
	struct s_PXENV_GET_FILE_SIZE		get_file_size;
	struct s_PXENV_FILE_EXEC		file_exec;
	struct s_PXENV_FILE_API_CHECK		file_api_check;
	struct s_PXENV_FILE_EXIT_HOOK		file_exit_hook;
};

typedef union u_PXENV_ANY PXENV_ANY_t;

/** A PXE API call */
struct pxe_api_call {
	/** Entry point
	 *
	 * @v params		PXE API call parameters
	 * @ret exit		PXE API call exit code
	 */
	PXENV_EXIT_t ( * entry ) ( union u_PXENV_ANY *params );
	/** Length of parameters */
	uint16_t params_len;
	/** Opcode */
	uint16_t opcode;
};

/** PXE API call table */
#define PXE_API_CALLS __table ( struct pxe_api_call, "pxe_api_calls" )

/** Declare a PXE API call */
#define __pxe_api_call __table_entry ( PXE_API_CALLS, 01 )

/**
 * Define a PXE API call
 *
 * @v _opcode		Opcode
 * @v _entry		Entry point
 * @v _params_type	Type of parameter structure
 * @ret call		PXE API call
 */
#define PXE_API_CALL( _opcode, _entry, _params_type ) {			      \
	.entry = ( ( ( ( PXENV_EXIT_t ( * ) ( _params_type *params ) ) NULL ) \
		    == ( ( typeof ( _entry ) * ) NULL ) )		      \
		   ? ( ( PXENV_EXIT_t ( * )				      \
			 ( union u_PXENV_ANY *params ) ) _entry )	      \
		   : ( ( PXENV_EXIT_t ( * )				      \
			 ( union u_PXENV_ANY *params ) ) _entry ) ),	      \
	.params_len = sizeof ( _params_type ),				      \
	.opcode = _opcode,						      \
	}

/** An UNDI expansion ROM header */
struct undi_rom_header {
	/** Signature
	 *
	 * Must be equal to @c ROM_SIGNATURE
	 */
	UINT16_t Signature;
	/** ROM length in 512-byte blocks */
	UINT8_t ROMLength;
	/** Unused */
	UINT8_t unused[0x13];
	/** Offset of the PXE ROM ID structure */
	UINT16_t PXEROMID;
	/** Offset of the PCI ROM structure */
	UINT16_t PCIRHeader;
} __attribute__ (( packed ));

/** Signature for an expansion ROM */
#define ROM_SIGNATURE 0xaa55

/** An UNDI ROM ID structure */
struct undi_rom_id {
	/** Signature
	 *
	 * Must be equal to @c UNDI_ROM_ID_SIGNATURE
	 */
	UINT32_t Signature;
	/** Length of structure */
	UINT8_t StructLength;
	/** Checksum */
	UINT8_t StructCksum;
	/** Structure revision
	 *
	 * Must be zero.
	 */
	UINT8_t StructRev;
	/** UNDI revision
	 *
	 * Version 2.1.0 is encoded as the byte sequence 0x00, 0x01, 0x02.
	 */
	UINT8_t UNDIRev[3];
	/** Offset to UNDI loader */
	UINT16_t UNDILoader;
	/** Minimum required stack segment size */
	UINT16_t StackSize;
	/** Minimum required data segment size */
	UINT16_t DataSize;
	/** Minimum required code segment size */
	UINT16_t CodeSize;
} __attribute__ (( packed ));

/** Signature for an UNDI ROM ID structure */
#define UNDI_ROM_ID_SIGNATURE \
	( ( 'U' << 0 ) + ( 'N' << 8 ) + ( 'D' << 16 ) + ( 'I' << 24 ) )

/** A PCI expansion header */
struct pcir_header {
	/** Signature
	 *
	 * Must be equal to @c PCIR_SIGNATURE
	 */
	uint32_t signature;
	/** PCI vendor ID */
	uint16_t vendor_id;
	/** PCI device ID */
	uint16_t device_id;
} __attribute__ (( packed ));

/** Signature for an UNDI ROM ID structure */
#define PCIR_SIGNATURE \
	( ( 'P' << 0 ) + ( 'C' << 8 ) + ( 'I' << 16 ) + ( 'R' << 24 ) )

extern struct net_device *pxe_netdev;
extern const char *pxe_cmdline;

extern void pxe_set_netdev ( struct net_device *netdev );
extern PXENV_EXIT_t pxenv_tftp_read_file ( struct s_PXENV_TFTP_READ_FILE
					   *tftp_read_file );
extern PXENV_EXIT_t undi_loader ( struct s_UNDI_LOADER *undi_loader );

#endif /* PXE_H */
