#ifndef _IPXE_SETTINGS_UI_H
#define _IPXE_SETTINGS_UI_H

/** @file
 *
 * Option configuration console
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

struct settings;

extern int settings_ui ( struct settings *settings ) __nonnull;

#endif /* _IPXE_SETTINGS_UI_H */
