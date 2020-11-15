/*
 *   Creation Date: <2002/10/03 21:07:27 samuel>
 *   Time-stamp: <2003/10/22 22:45:26 samuel>
 *
 *	<prom.h>
 *
 *	device tree interface
 *
 *   Copyright (C) 2002, 2003 Samuel Rydh (samuel@ibrium.se)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation
 *
 */

#ifndef _H_PROM
#define _H_PROM

/* Note 1: MOL uses -1 as the invalid phandle while OpenFirmware uses 0 as the
 * invalid phandle (it is also the root node).
 *
 * Note 2: phandles might be negative. For instance, phandles originating from
 * a real Open Firmware tree might look like 0xff123000 (a ROM address)...
 */

typedef enum { kGetRootPhandle=0 } mol_phandle_t;	/* must promote to int */

extern int			prom_close( void );

extern mol_phandle_t		prom_peer( mol_phandle_t phandle );
extern mol_phandle_t		prom_child( mol_phandle_t phandle );
extern mol_phandle_t		prom_parent( mol_phandle_t phandle );
extern int			prom_package_to_path( mol_phandle_t phandle, char *buf, long buflen );
extern int			prom_get_prop_len( mol_phandle_t phandle, const char *name );
extern int			prom_get_prop( mol_phandle_t phandle, const char *name, char *buf, long buflen );
extern int			prom_get_prop_by_path( const char *path, const char *name, char *buf, long buflen );
extern int			prom_next_prop( mol_phandle_t phandle, const char *prev, char *buf );
extern int			prom_set_prop( mol_phandle_t phandle, const char *name, char *buf, long buflen );
extern mol_phandle_t		prom_create_node( const char *path );
extern mol_phandle_t		prom_find_device( const char *path );

extern mol_phandle_t		prom_find_device_type( const char *type, int index );

extern int			prom_change_phandle( mol_phandle_t old_ph, mol_phandle_t new_ph );

#endif   /* _H_PROM */
