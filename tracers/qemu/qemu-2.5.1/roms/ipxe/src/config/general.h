#ifndef CONFIG_GENERAL_H
#define CONFIG_GENERAL_H

/** @file
 *
 * General configuration
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <config/defaults.h>

/*
 * Banner timeout configuration
 *
 * This controls the timeout for the "Press Ctrl-B for the iPXE
 * command line" banner displayed when iPXE starts up.  The value is
 * specified in tenths of a second for which the banner should appear.
 * A value of 0 disables the banner.
 *
 * ROM_BANNER_TIMEOUT controls the "Press Ctrl-B to configure iPXE"
 * banner displayed only by ROM builds of iPXE during POST.  This
 * defaults to being twice the length of BANNER_TIMEOUT, to allow for
 * BIOSes that switch video modes immediately before calling the
 * initialisation vector, thus rendering the banner almost invisible
 * to the user.
 */
#define BANNER_TIMEOUT		20
#define ROM_BANNER_TIMEOUT	( 2 * BANNER_TIMEOUT )

/*
 * Network protocols
 *
 */

#define	NET_PROTO_IPV4		/* IPv4 protocol */
#undef	NET_PROTO_IPV6		/* IPv6 protocol */
#undef	NET_PROTO_FCOE		/* Fibre Channel over Ethernet protocol */
#define	NET_PROTO_STP		/* Spanning Tree protocol */

/*
 * PXE support
 *
 */
//#undef	PXE_STACK		/* PXE stack in iPXE - you want this! */
//#undef	PXE_MENU		/* PXE menu booting */

/*
 * Download protocols
 *
 */

#define	DOWNLOAD_PROTO_TFTP	/* Trivial File Transfer Protocol */
#define	DOWNLOAD_PROTO_HTTP	/* Hypertext Transfer Protocol */
#undef	DOWNLOAD_PROTO_HTTPS	/* Secure Hypertext Transfer Protocol */
#undef	DOWNLOAD_PROTO_FTP	/* File Transfer Protocol */
#undef	DOWNLOAD_PROTO_SLAM	/* Scalable Local Area Multicast */
#undef	DOWNLOAD_PROTO_NFS	/* Network File System Protocol */

/*
 * SAN boot protocols
 *
 */

//#undef	SANBOOT_PROTO_ISCSI	/* iSCSI protocol */
//#undef	SANBOOT_PROTO_AOE	/* AoE protocol */
//#undef	SANBOOT_PROTO_IB_SRP	/* Infiniband SCSI RDMA protocol */
//#undef	SANBOOT_PROTO_FCP	/* Fibre Channel protocol */
//#undef	SANBOOT_PROTO_HTTP	/* HTTP SAN protocol */

/*
 * HTTP extensions
 *
 */
#define HTTP_AUTH_BASIC		/* Basic authentication */
#define HTTP_AUTH_DIGEST	/* Digest authentication */
//#define HTTP_ENC_PEERDIST	/* PeerDist content encoding */

/*
 * 802.11 cryptosystems and handshaking protocols
 *
 */
#define	CRYPTO_80211_WEP	/* WEP encryption (deprecated and insecure!) */
#define	CRYPTO_80211_WPA	/* WPA Personal, authenticating with passphrase */
#define	CRYPTO_80211_WPA2	/* Add support for stronger WPA cryptography */

/*
 * Name resolution modules
 *
 */

#define	DNS_RESOLVER		/* DNS resolver */

/*
 * Image types
 *
 * Etherboot supports various image formats.  Select whichever ones
 * you want to use.
 *
 */
//#define	IMAGE_NBI		/* NBI image support */
//#define	IMAGE_ELF		/* ELF image support */
//#define	IMAGE_MULTIBOOT		/* MultiBoot image support */
//#define	IMAGE_PXE		/* PXE image support */
//#define	IMAGE_SCRIPT		/* iPXE script image support */
//#define	IMAGE_BZIMAGE		/* Linux bzImage image support */
//#define	IMAGE_COMBOOT		/* SYSLINUX COMBOOT image support */
//#define	IMAGE_EFI		/* EFI image support */
//#define	IMAGE_SDI		/* SDI image support */
//#define	IMAGE_PNM		/* PNM image support */
//#define	IMAGE_PNG		/* PNG image support */

/*
 * Command-line commands to include
 *
 */
#define	AUTOBOOT_CMD		/* Automatic booting */
#define	NVO_CMD			/* Non-volatile option storage commands */
#define	CONFIG_CMD		/* Option configuration console */
#define	IFMGMT_CMD		/* Interface management commands */
#define	IWMGMT_CMD		/* Wireless interface management commands */
#define FCMGMT_CMD		/* Fibre Channel management commands */
#define	ROUTE_CMD		/* Routing table management commands */
#define IMAGE_CMD		/* Image management commands */
#define DHCP_CMD		/* DHCP management commands */
#define SANBOOT_CMD		/* SAN boot commands */
#define MENU_CMD		/* Menu commands */
#define LOGIN_CMD		/* Login command */
#define SYNC_CMD		/* Sync command */
//#define NSLOOKUP_CMD		/* DNS resolving command */
//#define TIME_CMD		/* Time commands */
//#define DIGEST_CMD		/* Image crypto digest commands */
//#define LOTEST_CMD		/* Loopback testing commands */
//#define VLAN_CMD		/* VLAN commands */
//#define PXE_CMD		/* PXE commands */
//#define REBOOT_CMD		/* Reboot command */
//#define POWEROFF_CMD		/* Power off command */
//#define IMAGE_TRUST_CMD	/* Image trust management commands */
//#define PCI_CMD		/* PCI commands */
//#define PARAM_CMD		/* Form parameter commands */
//#define NEIGHBOUR_CMD		/* Neighbour management commands */
//#define PING_CMD		/* Ping command */
//#define CONSOLE_CMD		/* Console command */
//#define IPSTAT_CMD		/* IP statistics commands */
//#define PROFSTAT_CMD		/* Profiling commands */

/*
 * ROM-specific options
 *
 */
#undef	NONPNP_HOOK_INT19	/* Hook INT19 on non-PnP BIOSes */
#define	AUTOBOOT_ROM_FILTER	/* Autoboot only devices matching our ROM */

/*
 * Error message tables to include
 *
 */
#undef	ERRMSG_80211		/* All 802.11 error descriptions (~3.3kb) */

/*
 * Obscure configuration options
 *
 * You probably don't need to touch these.
 *
 */

#undef	BUILD_SERIAL		/* Include an automatic build serial
				 * number.  Add "bs" to the list of
				 * make targets.  For example:
				 * "make bin/rtl8139.dsk bs" */
#undef	BUILD_ID		/* Include a custom build ID string,
				 * e.g "test-foo" */
#undef	NULL_TRAP		/* Attempt to catch NULL function calls */
#undef	GDBSERIAL		/* Remote GDB debugging over serial */
#undef	GDBUDP			/* Remote GDB debugging over UDP
				 * (both may be set) */
//#define EFI_DOWNGRADE_UX	/* Downgrade UEFI user experience */

#include <config/named.h>
#include NAMED_CONFIG(general.h)
#include <config/local/general.h>
#include LOCAL_NAMED_CONFIG(general.h)

#endif /* CONFIG_GENERAL_H */
