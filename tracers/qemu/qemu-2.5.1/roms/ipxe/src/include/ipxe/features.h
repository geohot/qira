#ifndef _IPXE_FEATURES_H
#define _IPXE_FEATURES_H

#include <stdint.h>
#include <ipxe/tables.h>
#include <ipxe/dhcp.h>

/** @file
 *
 * Feature list
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/**
 * @defgroup featurecat Feature categories
 * @{
 */

#define FEATURE_PROTOCOL		01 /**< Network protocols */
#define FEATURE_IMAGE			02 /**< Image formats */
#define FEATURE_MISC			03 /**< Miscellaneous */

/** @} */

/**
 * @defgroup dhcpfeatures DHCP feature option tags
 *
 * DHCP feature option tags are Etherboot encapsulated options in the
 * range 0x10-0x7f.
 *
 * @{
 */

#define DHCP_EB_FEATURE_PXE_EXT		0x10 /**< PXE API extensions */
#define DHCP_EB_FEATURE_ISCSI		0x11 /**< iSCSI protocol */
#define DHCP_EB_FEATURE_AOE		0x12 /**< AoE protocol */
#define DHCP_EB_FEATURE_HTTP		0x13 /**< HTTP protocol */
#define DHCP_EB_FEATURE_HTTPS		0x14 /**< HTTPS protocol */
#define DHCP_EB_FEATURE_TFTP		0x15 /**< TFTP protocol */
#define DHCP_EB_FEATURE_FTP		0x16 /**< FTP protocol */
#define DHCP_EB_FEATURE_DNS		0x17 /**< DNS protocol */
#define DHCP_EB_FEATURE_BZIMAGE		0x18 /**< bzImage format */
#define DHCP_EB_FEATURE_MULTIBOOT	0x19 /**< Multiboot format */
#define DHCP_EB_FEATURE_SLAM		0x1a /**< SLAM protocol */
#define DHCP_EB_FEATURE_SRP		0x1b /**< SRP protocol */
#define DHCP_EB_FEATURE_NBI		0x20 /**< NBI format */
#define DHCP_EB_FEATURE_PXE		0x21 /**< PXE format */
#define DHCP_EB_FEATURE_ELF		0x22 /**< ELF format */
#define DHCP_EB_FEATURE_COMBOOT		0x23 /**< COMBOOT format */
#define DHCP_EB_FEATURE_EFI		0x24 /**< EFI format */
#define DHCP_EB_FEATURE_FCOE		0x25 /**< FCoE protocol */
#define DHCP_EB_FEATURE_VLAN		0x26 /**< VLAN support */
#define DHCP_EB_FEATURE_MENU		0x27 /**< Menu support */
#define DHCP_EB_FEATURE_SDI		0x28 /**< SDI image support */
#define DHCP_EB_FEATURE_NFS		0x29 /**< NFS protocol */

/** @} */

/** DHCP feature table */
#define DHCP_FEATURES __table ( uint8_t, "dhcp_features" )

/** Declare a feature code for DHCP */
#define __dhcp_feature __table_entry ( DHCP_FEATURES, 01 )

/** Construct a DHCP feature table entry */
#define DHCP_FEATURE( feature_opt, ... )				    \
	_DHCP_FEATURE ( OBJECT, feature_opt, __VA_ARGS__ )
#define _DHCP_FEATURE( _name, feature_opt, ... )			    \
	__DHCP_FEATURE ( _name, feature_opt, __VA_ARGS__ )
#define __DHCP_FEATURE( _name, feature_opt, ... )			    \
	uint8_t __dhcp_feature_ ## _name [] __dhcp_feature = {		    \
		feature_opt, DHCP_OPTION ( __VA_ARGS__ )		    \
	};

/** A named feature */
struct feature {
	/** Feature name */
	char *name;
};

/** Named feature table */
#define FEATURES __table ( struct feature, "features" )

/** Declare a named feature */
#define __feature_name( category ) __table_entry ( FEATURES, category )

/** Construct a named feature */
#define FEATURE_NAME( category, text )					    \
	_FEATURE_NAME ( category, OBJECT, text )
#define _FEATURE_NAME( category, _name, text )				    \
	__FEATURE_NAME ( category, _name, text )
#define __FEATURE_NAME( category, _name, text )				    \
	struct feature __feature_ ## _name __feature_name ( category ) = {  \
		.name = text,						    \
	};

/** Declare a feature */
#define FEATURE( category, text, feature_opt, version )			    \
	FEATURE_NAME ( category, text );				    \
	DHCP_FEATURE ( feature_opt, version );

/** Declare the version number feature */
#define FEATURE_VERSION( ... )						    \
	DHCP_FEATURE ( DHCP_ENCAPSULATED ( DHCP_EB_VERSION ), __VA_ARGS__ )

#endif /* _IPXE_FEATURES_H */
