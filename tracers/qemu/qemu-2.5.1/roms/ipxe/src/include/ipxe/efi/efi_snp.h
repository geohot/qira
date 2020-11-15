#ifndef _IPXE_EFI_SNP_H
#define _IPXE_EFI_SNP_H

/** @file
 *
 * iPXE EFI SNP interface
 *
 */

#include <ipxe/list.h>
#include <ipxe/netdevice.h>
#include <ipxe/efi/efi.h>
#include <ipxe/efi/Protocol/SimpleNetwork.h>
#include <ipxe/efi/Protocol/NetworkInterfaceIdentifier.h>
#include <ipxe/efi/Protocol/ComponentName2.h>
#include <ipxe/efi/Protocol/DevicePath.h>
#include <ipxe/efi/Protocol/HiiConfigAccess.h>
#include <ipxe/efi/Protocol/HiiDatabase.h>
#include <ipxe/efi/Protocol/LoadFile.h>

/** SNP transmit completion ring size */
#define EFI_SNP_NUM_TX 32

/** An SNP device */
struct efi_snp_device {
	/** List of SNP devices */
	struct list_head list;
	/** The underlying iPXE network device */
	struct net_device *netdev;
	/** The underlying EFI device */
	struct efi_device *efidev;
	/** EFI device handle */
	EFI_HANDLE handle;
	/** The SNP structure itself */
	EFI_SIMPLE_NETWORK_PROTOCOL snp;
	/** The SNP "mode" (parameters) */
	EFI_SIMPLE_NETWORK_MODE mode;
	/** Started flag */
	int started;
	/** Pending interrupt status */
	unsigned int interrupts;
	/** Transmit completion ring */
	VOID *tx[EFI_SNP_NUM_TX];
	/** Transmit completion ring producer counter */
	unsigned int tx_prod;
	/** Transmit completion ring consumer counter */
	unsigned int tx_cons;
	/** Receive queue */
	struct list_head rx;
	/** The network interface identifier */
	EFI_NETWORK_INTERFACE_IDENTIFIER_PROTOCOL nii;
	/** Component name protocol */
	EFI_COMPONENT_NAME2_PROTOCOL name2;
	/** Load file protocol handle */
	EFI_LOAD_FILE_PROTOCOL load_file;
	/** HII configuration access protocol */
	EFI_HII_CONFIG_ACCESS_PROTOCOL hii;
	/** HII package list */
	EFI_HII_PACKAGE_LIST_HEADER *package_list;
	/** HII handle */
	EFI_HII_HANDLE hii_handle;
	/** Device name */
	wchar_t name[ sizeof ( ( ( struct net_device * ) NULL )->name ) ];
	/** Driver name */
	wchar_t driver_name[16];
	/** Controller name */
	wchar_t controller_name[64];
	/** The device path */
	EFI_DEVICE_PATH_PROTOCOL *path;
};

extern int efi_snp_hii_install ( struct efi_snp_device *snpdev );
extern void efi_snp_hii_uninstall ( struct efi_snp_device *snpdev );
extern struct efi_snp_device * find_snpdev ( EFI_HANDLE handle );
extern struct efi_snp_device * last_opened_snpdev ( void );
extern void efi_snp_set_claimed ( int claimed );

/**
 * Claim network devices for use by iPXE
 *
 */
static inline void efi_snp_claim ( void ) {
	efi_snp_set_claimed ( 1 );
}

/**
 * Release network devices for use via SNP
 *
 */
static inline void efi_snp_release ( void ) {
	efi_snp_set_claimed ( 0 );
}

#endif /* _IPXE_EFI_SNP_H */
