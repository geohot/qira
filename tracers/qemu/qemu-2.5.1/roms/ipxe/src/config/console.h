#ifndef CONFIG_CONSOLE_H
#define CONFIG_CONSOLE_H

/** @file
 *
 * Console configuration
 *
 * These options specify the console types that Etherboot will use for
 * interaction with the user.
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <config/defaults.h>

//#define	CONSOLE_PCBIOS		/* Default BIOS console */
//#define	CONSOLE_SERIAL		/* Serial port */
//#define	CONSOLE_DIRECT_VGA	/* Direct access to VGA card */
//#define	CONSOLE_PC_KBD		/* Direct access to PC keyboard */
//#define	CONSOLE_SYSLOG		/* Syslog console */
//#define	CONSOLE_SYSLOGS		/* Encrypted syslog console */
//#define	CONSOLE_VMWARE		/* VMware logfile console */
//#define	CONSOLE_DEBUGCON	/* Debug port console */
//#define	CONSOLE_VESAFB		/* VESA framebuffer console */
//#define	CONSOLE_INT13		/* INT13 disk log console */

#define	KEYBOARD_MAP	us

#define	LOG_LEVEL	LOG_NONE

#include <config/named.h>
#include NAMED_CONFIG(console.h)
#include <config/local/console.h>
#include LOCAL_NAMED_CONFIG(console.h)

#endif /* CONFIG_CONSOLE_H */
