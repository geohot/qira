<?php // -*- Mode: PHP; -*-

/**
 * Copyright (C) 2009 Marty Connor <mdc@etherboot.org>.
 * Copyright (C) 2009 Entity Cyber, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

$ofmts = array
	( "Floppy bootable image (.dsk)" => "dsk",
	  "SYSLINUX-based bootable floppy image (.sdsk)" => "sdsk",
	  "ISO bootable image (.iso)" => "iso",
	  "ISO bootable image with legacy floppy emulation (.liso)" => "liso",
	  "Linux kernel (SYSLINUX/GRUB/LILO) loadable image (.lkrn)" => "lkrn",
	  "USB Keychain disk image (.usb)" => "usb",
	  "ROM binary (flashable) image (.rom)" => "rom",
	  "ROM binary (flashable) for problem PMM BIOSES  (.hrom)" => "hrom",
	  "PXE bootstrap loader image [Unload PXE stack] (.pxe)" => "pxe",
	  "PXE bootstrap loader keep [Keep PXE stack method 1] (.kpxe)" => "kpxe",
	  "PXE bootstrap loader keep [Keep PXE stack method 2] (.kkpxe)" => "kkpxe",
	);

$flag_table = array (

	// Begin General Options:

	"HDR_MISC_OPTIONS"
	=> array (
	   "flag" => "HDR_MISC_OPTIONS",
	   "hide_from_user" => "yes",  // Hide even the header
	   "type" => "header",
	   "label" => "Miscellaneous Options"
		),

	"PRODUCT_NAME"
	=> array (
	   "flag" => "PRODUCT_NAME",
	   "hide_from_user" => "yes",
	   "type" => "string",
	   "value" => "",
	   "cfgsec" => "general"
	   ),

	"PRODUCT_SHORT_NAME"
	=> array (
	   "flag" => "PRODUCT_SHORT_NAME",
	   "hide_from_user" => "yes",
	   "type" => "string",
	   "value" => "iPXE",
	   "cfgsec" => "general"
	   ),

	// End General Options:

	// Begin Console Options:

	"HDR_CONSOLE_OPTIONS"
	=> array (
	   "flag" => "HDR_CONSOLE_OPTIONS",
	   "type" => "header",
	   "label" => "Console Options"
		),

	"CONSOLE_PCBIOS"
	=> array (
	   "flag" => "CONSOLE_PCBIOS",
	   "type" => "on/off",
	   "value" => "on",
	   "cfgsec" => "console"
	   ),

	"CONSOLE_SERIAL"
	=> array (
	   "flag" => "CONSOLE_SERIAL",
	   "type" => "on/off",
	   "value" => "off",
	   "cfgsec" => "console"
	   ),

	"BANNER_TIMEOUT"
	=> array (
	   "flag" => "BANNER_TIMEOUT",
	   "type" => "integer",
	   "value" => "20",
	   "cfgsec" => "general"
	   ),

        "KEYBOARD_MAP"
        => array (
           "flag" => "KEYBOARD_MAP",
           "type" => "choice",
	   "options" => array("al","az","bg","by","cf","cz","de","dk","es","et","fi","fr",
	      "gr","hu","il","it","lt","mk","mt","nl","no","pl","pt","ro","ru","sg","sr",
	      "th","ua","uk","us","wo"),
           "value" => "us",
           "cfgsec" => "console"
           ),

	"LOG_LEVEL"
	=> array (
	   "flag" => "LOG_LEVEL",
	   "type" => "choice",
	   "options" => array("LOG_NONE","LOG_EMERG","LOG_ALERT","LOG_CRIT","LOG_ERR",
	      "LOG_WARNING","LOG_NOTICE","LOG_INFO","LOG_DEBUG","LOG_ALL"),
	   "value" => "LOG_NONE",
	   "cfgsec" => "console"
	   ),

	// End Console Options

	// Begin Network Protocol Options:

	"HDR_NETWORK_PROTOCOL_OPTIONS"
	=> array (
	   "flag" => "HDR_NETWORK_PROTOCOL_OPTIONS",
	   "hide_from_user" => "yes",  // Hide even the header
	   "type" => "header",
	   "label" => "Network Protocol Options"
		),

	"NET_PROTO_IPV4"
	=> array (
	   "flag" => "NET_PROTO_IPV4",
	   "type" => "on/off",
	   "value" => "on",
	   "hide_from_user" => "yes",
	   "cfgsec" => "general"
	   ),

	// End Network Protocol Options

	// Begin Serial Port configuration

	"HDR_SERIAL_PORT_OPTIONS"
	=> array (
	   "flag" => "HDR_SERIAL_PORT_OPTIONS",
	   "type" => "header",
	   "label" => "Serial Port Options"
		),

	"COMCONSOLE"
	=> array (
	   "flag" => "COMCONSOLE",
	   "type" => "integer-hex", // e.g. 0x378
	   "value" => "0x3F8",
	   "cfgsec" => "serial"
		),

	"COMPRESERVE"
	=> array (
	   "flag" => "COMPRESERVE",
	   "type" => "on/off",
	   "value" => "off",
	   "cfgsec" => "serial"
	   ),

	"COMSPEED"
	=> array (
	   "flag" => "COMSPEED",
	   "type" => "integer",
	   "value" => "115200",
	   "cfgsec" => "serial"
	   ),

	"COMDATA"
	=> array (
	   "flag" => "COMDATA",
	   "type" => "integer",
	   "value" => "8",
	   "cfgsec" => "serial"
	   ),

	"COMPARITY"
	=> array (
	   "flag" => "COMPARITY",
	   "type" => "integer",
	   "value" => "0",
	   "cfgsec" => "serial"
	   ),

	"COMSTOP"
	=> array (
	   "flag" => "COMSTOP",
	   "type" => "integer",
	   "value" => "1",
	   "cfgsec" => "serial"
	   ),

	// End Serial Options

	// Begin Download Protocols

	"HDR_DOWNLOAD_PROTOCOLS"
	=> array (
	   "flag" => "HDR_DOWNLOAD_PROTOCOLS",
	   "type" => "header",
	   "label" => "Download Protocols"
		),

	"DOWNLOAD_PROTO_TFTP"
	=> array (
	   "flag" => "DOWNLOAD_PROTO_TFTP",
	   "type" => "on/off",
	   "value" => "on",
	   "cfgsec" => "general"
	   ),

	"DOWNLOAD_PROTO_HTTP"
	=> array (
	   "flag" => "DOWNLOAD_PROTO_HTTP",
	   "type" => "on/off",
	   "value" => "on",
	   "cfgsec" => "general"
	   ),

	"DOWNLOAD_PROTO_HTTPS"
	=> array (
	   "flag" => "DOWNLOAD_PROTO_HTTPS",
	   "type" => "on/off",
	   "value" => "off",
	   "cfgsec" => "general"
	   ),

	"DOWNLOAD_PROTO_FTP"
	=> array (
	   "flag" => "DOWNLOAD_PROTO_FTP",
	   "type" => "on/off",
	   "value" => "off",
	   "cfgsec" => "general"
	   ),

	// End Download Protocols

	// Begin SAN boot protocols

	"HDR_SANBOOT_PROTOCOLS"
	=> array (
	   "flag" => "HDR_SANBOOT_PROTOCOLS",
	   "type" => "header",
	   "label" => "SAN Boot Protocols"
		),

	"SANBOOT_PROTO_ISCSI"
	=> array (
	   "flag" => "SANBOOT_PROTO_ISCSI",
	   "type" => "on/off",
	   "value" => "on",
	   "cfgsec" => "general"
	   ),

	"SANBOOT_PROTO_AOE"
	=> array (
	   "flag" => "SANBOOT_PROTO_AOE",
	   "type" => "on/off",
	   "value" => "on",
	   "cfgsec" => "general"
	   ),

	// End SAN boot protocols

	// Begin Name resolution modules

	"HDR_NAME_RESOLUTION_MODULES"
	=> array (
	   "flag" => "HDR_NAME_RESOLUTION_MODULES",
	   "type" => "header",
	   "label" => "Name Resolution Modules"
	   ),

	"DNS_RESOLVER"
	=> array (
	   "flag" => "DNS_RESOLVER",
	   "type" => "on/off",
	   "value" => "on",
	   "cfgsec" => "general"
		),

	"NMB_RESOLVER"
	=> array (
	   "flag" => "NMB_RESOLVER",
	   "type" => "on/off",
	   "value" => "off",
	   "hide_from_user" => "yes",
	   "cfgsec" => "general"
		),

	// End Name resolution modules

	// Begin Image types

	"HDR_IMAGE_TYPES"
	=> array (
	   "flag" => "HDR_IMAGE_TYPES",
	   "type" => "header",
	   "label" => "Image Types",
	   ),

	"IMAGE_ELF"
	=> array (
	   "flag" => "IMAGE_ELF",
	   "type" => "on/off",
	   "value" => "on",
	   "cfgsec" => "general"
	   ),

	"IMAGE_NBI"
	=> array (
	   "flag" => "IMAGE_NBI",
	   "type" => "on/off",
	   "value" => "on",
	   "cfgsec" => "general"
		),

	"IMAGE_MULTIBOOT"
	=> array (
	   "flag" => "IMAGE_MULTIBOOT",
	   "type" => "on/off",
	   "value" => "on",
	   "cfgsec" => "general"
	   ),

	"IMAGE_PXE"
	=> array (
	   "flag" => "IMAGE_PXE",
	   "type" => "on/off",
	   "value" => "on",
	   "cfgsec" => "general"
	   ),

	"IMAGE_SCRIPT"
	=> array (
	   "flag" => "IMAGE_SCRIPT",
	   "type" => "on/off",
	   "value" => "on",
	   "cfgsec" => "general"
	   ),

	"IMAGE_BZIMAGE"
	=> array (
	   "flag" => "IMAGE_BZIMAGE",
	   "type" => "on/off",
	   "value" => "on",
	   "cfgsec" => "general"
	   ),

	"IMAGE_COMBOOT"
	=> array (
	   "flag" => "IMAGE_COMBOOT",
	   "type" => "on/off",
	   "value" => "on",
	   "cfgsec" => "general"
	   ),

	// End Image types

	// Begin Command-line commands to include

	"HDR_COMMAND_LINE_OPTIONS"
	=> array (
	   "flag" => "HDR_COMMAND_LINE_OPTIONS",
	   "type" => "header",
	   "label" => "Command Line Options",
	   ),

	"AUTOBOOT_CMD"
	=> array (
	   "flag" => "AUTOBOOT_CMD",
	   "type" => "on/off",
	   "value" => "on",
	   "cfgsec" => "general"
	   ),

	"NVO_CMD"
	=> array (
	   "flag" => "NVO_CMD",
	   "type" => "on/off",
	   "value" => "on",
	   "cfgsec" => "general"
	   ),

	"CONFIG_CMD"
	=> array (
	   "flag" => "CONFIG_CMD",
	   "type" => "on/off",
	   "value" => "on",
	   "cfgsec" => "general"
	   ),

	"IFMGMT_CMD"
	=> array (
	   "flag" => "IFMGMT_CMD",
	   "type" => "on/off",
	   "value" => "on",
	   "cfgsec" => "general"
	   ),

	"IWMGMT_CMD"
	=> array (
	   "flag" => "IWMGMT_CMD",
	   "type" => "on/off",
	   "value" => "on",
	   "cfgsec" => "general"
	   ),

	"ROUTE_CMD"
	=> array (
	   "flag" => "ROUTE_CMD",
	   "type" => "on/off",
	   "value" => "on",
	   "cfgsec" => "general"
	   ),

	"IMAGE_CMD"
	=> array (
	   "flag" => "IMAGE_CMD",
	   "type" => "on/off",
	   "value" => "on",
	   "cfgsec" => "general"
	   ),

	"DHCP_CMD"
	=> array (
	   "flag" => "DHCP_CMD",
	   "type" => "on/off",
	   "value" => "on",
	   "cfgsec" => "general"
		),

	"SANBOOT_CMD"
	=> array (
	   "flag" => "SANBOOT_CMD",
	   "type" => "on/off",
	   "value" => "on",
	   "cfgsec" => "general"
		),

	"LOGIN_CMD"
	=> array (
	   "flag" => "LOGIN_CMD",
	   "type" => "on/off",
	   "value" => "on",
	   "cfgsec" => "general"
		),

	"TIME_CMD"
	=> array (
	   "flag" => "TIME_CMD",
	   "type" => "on/off",
	   "value" => "off",
	   "cfgsec" => "general"
		),

	"DIGEST_CMD"
	=> array (
	   "flag" => "DIGEST_CMD",
	   "type" => "on/off",
	   "value" => "off",
	   "cfgsec" => "general"
		),

	// End Command-line commands to include

	// Begin Wireless options

	"HDR_WIRELESS_OPTIONS"
	=> array (
	   "flag" => "HDR_WIRELESS_OPTIONS",
	   "type" => "header",
	   "label" => "Wireless Interface Options",
	   ),

	"CRYPTO_80211_WEP"
	=> array (
	   "flag" => "CRYPTO_80211_WEP",
	   "type" => "on/off",
	   "value" => "on",
	   "cfgsec" => "general"
	   ),

	"CRYPTO_80211_WPA"
	=> array (
	   "flag" => "CRYPTO_80211_WPA",
	   "type" => "on/off",
	   "value" => "on",
	   "cfgsec" => "general"
	   ),

	"CRYPTO_80211_WPA2"
	=> array (
	   "flag" => "CRYPTO_80211_WPA2",
	   "type" => "on/off",
	   "value" => "on",
	   "cfgsec" => "general"
	   ),

	// End Wireless options

	// Obscure options required to compile
	"NETDEV_DISCARD_RATE"
	=> array (
	   "flag" => "NETDEV_DISCARD_RATE",
	   "type" => "integer",
	   "value" => "0",
	   "cfgsec" => "general",
	   "hide_from_user" => true
	   )

	// End Obscure options
);

// For emacs:
// Local variables:
//	c-basic-offset: 4
//	c-indent-level: 4
//	tab-width: 4
// End:

?>
