/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * You can also choose to distribute this program under the terms of
 * the Unmodified Binary Distribution Licence (as given in the file
 * COPYING.UBDL), provided that you have satisfied its requirements.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <config/general.h>
#include <config/console.h>
#include <config/sideband.h>
#include <config/settings.h>

/** @file
 *
 * Configuration options
 *
 * This file contains macros that pull various objects into the link
 * based on definitions in configuration header files. Ideally it
 * should be the only place in iPXE where one might need to use #ifdef
 * for compile-time options.
 *
 * In the fairly common case where an object should only be considered
 * for inclusion if the subsystem it depends on is present, its
 * configuration macros should be placed in a file named
 * <tt>config_<i>subsystem</i>.c</tt>, where @e subsystem is the
 * object basename of the main source file for that subsystem. The
 * build system will pull in that file if @c subsystem.c is included
 * in the final iPXE executable built.
 */

PROVIDE_REQUIRING_SYMBOL();

/*
 * Drag in all requested console types
 *
 */

#ifdef CONSOLE_PCBIOS
REQUIRE_OBJECT ( bios_console );
#endif
#ifdef CONSOLE_SERIAL
REQUIRE_OBJECT ( serial );
#endif
#ifdef CONSOLE_DIRECT_VGA
REQUIRE_OBJECT ( video_subr );
#endif
#ifdef CONSOLE_PC_KBD
REQUIRE_OBJECT ( pc_kbd );
#endif
#ifdef CONSOLE_SYSLOG
REQUIRE_OBJECT ( syslog );
#endif
#ifdef CONSOLE_SYSLOGS
REQUIRE_OBJECT ( syslogs );
#endif
#ifdef CONSOLE_EFI
REQUIRE_OBJECT ( efi_console );
#endif
#ifdef CONSOLE_LINUX
REQUIRE_OBJECT ( linux_console );
#endif
#ifdef CONSOLE_VMWARE
REQUIRE_OBJECT ( vmconsole );
#endif
#ifdef CONSOLE_DEBUGCON
REQUIRE_OBJECT ( debugcon );
#endif
#ifdef CONSOLE_VESAFB
REQUIRE_OBJECT ( vesafb );
#endif
#ifdef CONSOLE_INT13
REQUIRE_OBJECT ( int13con );
#endif

/*
 * Drag in all requested network protocols
 *
 */
#ifdef NET_PROTO_IPV4
REQUIRE_OBJECT ( ipv4 );
#endif
#ifdef NET_PROTO_IPV6
REQUIRE_OBJECT ( ipv6 );
#endif

/*
 * Drag in all requested PXE support
 *
 */
#ifdef PXE_MENU
REQUIRE_OBJECT ( pxemenu );
#endif
#ifdef PXE_STACK
REQUIRE_OBJECT ( pxe_call );
#endif

/*
 * Drag in all requested download protocols
 *
 */
#ifdef DOWNLOAD_PROTO_TFTP
REQUIRE_OBJECT ( tftp );
#endif
#ifdef DOWNLOAD_PROTO_HTTP
REQUIRE_OBJECT ( http );
#endif
#ifdef DOWNLOAD_PROTO_HTTPS
REQUIRE_OBJECT ( https );
#endif
#ifdef DOWNLOAD_PROTO_FTP
REQUIRE_OBJECT ( ftp );
#endif
#ifdef DOWNLOAD_PROTO_NFS
REQUIRE_OBJECT ( nfs_open );
#endif
#ifdef DOWNLOAD_PROTO_SLAM
REQUIRE_OBJECT ( slam );
#endif

/*
 * Drag in all requested SAN boot protocols
 *
 */
#ifdef SANBOOT_PROTO_ISCSI
REQUIRE_OBJECT ( iscsi );
#endif
#ifdef SANBOOT_PROTO_HTTP
REQUIRE_OBJECT ( httpblock );
#endif

/*
 * Drag in all requested resolvers
 *
 */
#ifdef DNS_RESOLVER
REQUIRE_OBJECT ( dns );
#endif

/*
 * Drag in all requested image formats
 *
 */
#ifdef IMAGE_NBI
REQUIRE_OBJECT ( nbi );
#endif
#ifdef IMAGE_ELF
REQUIRE_OBJECT ( elfboot );
#endif
#ifdef IMAGE_MULTIBOOT
REQUIRE_OBJECT ( multiboot );
#endif
#ifdef IMAGE_PXE
REQUIRE_OBJECT ( pxe_image );
#endif
#ifdef IMAGE_SCRIPT
REQUIRE_OBJECT ( script );
#endif
#ifdef IMAGE_BZIMAGE
REQUIRE_OBJECT ( bzimage );
#endif
#ifdef IMAGE_ELTORITO
REQUIRE_OBJECT ( eltorito );
#endif
#ifdef IMAGE_COMBOOT
REQUIRE_OBJECT ( comboot );
REQUIRE_OBJECT ( com32 );
REQUIRE_OBJECT ( comboot_call );
REQUIRE_OBJECT ( com32_call );
REQUIRE_OBJECT ( com32_wrapper );
REQUIRE_OBJECT ( comboot_resolv );
#endif
#ifdef IMAGE_EFI
REQUIRE_OBJECT ( efi_image );
#endif
#ifdef IMAGE_SDI
REQUIRE_OBJECT ( sdi );
#endif
#ifdef IMAGE_PNM
REQUIRE_OBJECT ( pnm );
#endif
#ifdef IMAGE_PNG
REQUIRE_OBJECT ( png );
#endif

/*
 * Drag in all requested commands
 *
 */
#ifdef AUTOBOOT_CMD
REQUIRE_OBJECT ( autoboot_cmd );
#endif
#ifdef NVO_CMD
REQUIRE_OBJECT ( nvo_cmd );
#endif
#ifdef CONFIG_CMD
REQUIRE_OBJECT ( config_cmd );
#endif
#ifdef IFMGMT_CMD
REQUIRE_OBJECT ( ifmgmt_cmd );
#endif
/* IWMGMT_CMD is brought in by net80211.c if requested */
#ifdef ROUTE_CMD
REQUIRE_OBJECT ( route_cmd );
#endif
#ifdef IMAGE_CMD
REQUIRE_OBJECT ( image_cmd );
#endif
#ifdef IMAGE_TRUST_CMD
REQUIRE_OBJECT ( image_trust_cmd );
#endif
#ifdef DHCP_CMD
REQUIRE_OBJECT ( dhcp_cmd );
#endif
#ifdef SANBOOT_CMD
REQUIRE_OBJECT ( sanboot_cmd );
#endif
#ifdef MENU_CMD
REQUIRE_OBJECT ( menu_cmd );
#endif
#ifdef LOGIN_CMD
REQUIRE_OBJECT ( login_cmd );
#endif
#ifdef TIME_CMD
REQUIRE_OBJECT ( time_cmd );
#endif
#ifdef DIGEST_CMD
REQUIRE_OBJECT ( digest_cmd );
#endif
#ifdef PXE_CMD
REQUIRE_OBJECT ( pxe_cmd );
#endif
#ifdef LOTEST_CMD
REQUIRE_OBJECT ( lotest_cmd );
#endif
#ifdef VLAN_CMD
REQUIRE_OBJECT ( vlan_cmd );
#endif
#ifdef POWEROFF_CMD
REQUIRE_OBJECT ( poweroff_cmd );
#endif
#ifdef REBOOT_CMD
REQUIRE_OBJECT ( reboot_cmd );
#endif
#ifdef CPUID_CMD
REQUIRE_OBJECT ( cpuid_cmd );
#endif
#ifdef SYNC_CMD
REQUIRE_OBJECT ( sync_cmd );
#endif
#ifdef NSLOOKUP_CMD
REQUIRE_OBJECT ( nslookup_cmd );
#endif
#ifdef PCI_CMD
REQUIRE_OBJECT ( pci_cmd );
#endif
#ifdef PARAM_CMD
REQUIRE_OBJECT ( param_cmd );
#endif
#ifdef NEIGHBOUR_CMD
REQUIRE_OBJECT ( neighbour_cmd );
#endif
#ifdef PING_CMD
REQUIRE_OBJECT ( ping_cmd );
#endif
#ifdef CONSOLE_CMD
REQUIRE_OBJECT ( console_cmd );
#endif
#ifdef IPSTAT_CMD
REQUIRE_OBJECT ( ipstat_cmd );
#endif
#ifdef PROFSTAT_CMD
REQUIRE_OBJECT ( profstat_cmd );
#endif

/*
 * Drag in miscellaneous objects
 *
 */
#ifdef NULL_TRAP
REQUIRE_OBJECT ( nulltrap );
#endif
#ifdef GDBSERIAL
REQUIRE_OBJECT ( gdbidt );
REQUIRE_OBJECT ( gdbserial );
REQUIRE_OBJECT ( gdbstub_cmd );
#endif
#ifdef GDBUDP
REQUIRE_OBJECT ( gdbidt );
REQUIRE_OBJECT ( gdbudp );
REQUIRE_OBJECT ( gdbstub_cmd );
#endif

/*
 * Drag in objects that are always required, but not dragged in via
 * symbol dependencies.
 *
 */
REQUIRE_OBJECT ( device );
REQUIRE_OBJECT ( embedded );

/* linux drivers aren't picked up by the parserom utility so drag them in here */
#ifdef DRIVERS_LINUX
REQUIRE_OBJECT ( tap );
#endif

/*
 * Drag in relevant sideband entry points
 */
#ifdef CONFIG_BOFM
#ifdef BOFM_EFI
REQUIRE_OBJECT ( efi_bofm );
#endif /* BOFM_EFI */
#endif /* CONFIG_BOFM */

/*
 * Drag in relevant settings sources
 */
#ifdef PCI_SETTINGS
REQUIRE_OBJECT ( pci_settings );
#endif
#ifdef VMWARE_SETTINGS
REQUIRE_OBJECT ( guestinfo );
#endif
#ifdef CPUID_SETTINGS
REQUIRE_OBJECT ( cpuid_settings );
#endif
#ifdef MEMMAP_SETTINGS
REQUIRE_OBJECT ( memmap_settings );
#endif
#ifdef VRAM_SETTINGS
REQUIRE_OBJECT ( vram_settings );
#endif

/*
 * Drag in selected keyboard map
 */
#define REQUIRE_KEYMAP_OBJECT( _map ) REQUIRE_OBJECT ( keymap_ ## _map )
#define REQUIRE_KEYMAP( _map ) REQUIRE_KEYMAP_OBJECT ( _map )
REQUIRE_KEYMAP ( KEYBOARD_MAP );
