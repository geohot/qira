/*
 *   Creation Date: <2002/10/03 20:55:02 samuel>
 *   Time-stamp: <2002/10/29 13:00:23 samuel>
 *
 *	<prom.c>
 *
 *	oftree interface
 *
 *   Copyright (C) 2002, 2003 Samuel Rydh (samuel@ibrium.se)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation
 *
 */

#include "config.h"
#include "osi_calls.h"
#include "mol/prom.h"

/* OSI_PromClose (free linux side device tree) */
int
prom_close( void )
{
	return OSI_PromIface( kPromClose, 0 );
}

/* ret: 0 no more peers, -1 if error */
mol_phandle_t
prom_peer( mol_phandle_t phandle )
{
	return OSI_PromIface( kPromPeer, phandle );
}

/* ret: 0 no child, -1 if error */
mol_phandle_t
prom_child( mol_phandle_t phandle )
{
	return OSI_PromIface( kPromChild, phandle );
}

/* ret: 0 if root node, -1 if error */
mol_phandle_t
prom_parent( mol_phandle_t phandle )
{
	return OSI_PromIface( kPromParent, phandle );
}

/* ret: -1 error */
int
prom_package_to_path( mol_phandle_t phandle, char *buf, long buflen )
{
	return OSI_PromIface2( kPromPackageToPath, phandle, (int)buf, buflen );
}

/* ret: -1 error */
int
prom_get_prop_len( mol_phandle_t phandle, const char *name )
{
	return OSI_PromIface1( kPromGetPropLen, phandle, (int)name );
}

/* ret: prop len or -1 if error */
int
prom_get_prop( mol_phandle_t phandle, const char *name, char *buf, long buflen )
{
	return OSI_PromIface3( kPromGetProp, phandle, (int)name, (int)buf, buflen );
}

/* ret: prop len or -1 if error */
int
prom_get_prop_by_path( const char *path, const char *name, char *buf, long buflen )
{
	mol_phandle_t ph = prom_find_device(path);
	return (ph != -1)? prom_get_prop( ph, name, buf, buflen) : -1;
}

/* ret: -1 error, 0 last prop, 1 otherwise */
int
prom_next_prop( mol_phandle_t phandle, const char *prev, char *buf )
{
	return OSI_PromIface2( kPromNextProp, phandle, (int)prev, (int)buf );
}

/* ret: -1 if error */
int
prom_set_prop( mol_phandle_t phandle, const char *name, char *buf, long buflen )
{
	return OSI_PromIface3( kPromSetProp, phandle, (int)name, (int)buf, buflen );
}

/* ret: -1 if error */
mol_phandle_t
prom_create_node( const char *path )
{
	return OSI_PromPathIface( kPromCreateNode, path );
}

/* ret: -1 if not found */
mol_phandle_t
prom_find_device( const char *path )
{
	mol_phandle_t ph;
	char buf2[256], ch, *p;

	if( !path )
		return -1;

	if( (ph=OSI_PromPathIface( kPromFindDevice, path )) != -1 )
		return ph;
	else if( path[0] == '/' )
		return -1;

	/* might be an alias */
	if( !(p=strpbrk(path, "@:/")) )
		p = (char*)path + strlen(path);

	ch = *p;
	*p = 0;
	if( (ph=prom_get_prop(prom_find_device("/aliases"), path, buf2, sizeof(buf2))) == -1 )
		return -1;
	*p = ch;
	strncat( buf2, p, sizeof(buf2) );

	if( buf2[0] != '/' ) {
		printk("Error: aliases must be absolute!\n");
		return -1;
	}
	ph = OSI_PromPathIface( kPromFindDevice, buf2 );
	return ph;
}



/************************************************************************/
/*	search the tree for nodes with matching device_type		*/
/************************************************************************/

static mol_phandle_t
prom_find_device_type_( mol_phandle_t ph, const char *type, int *icount, int index )
{
	char buf[64];
	int ph2;

	if( ph == -1 || !ph )
		return -1;
	if( prom_get_prop( ph, "device_type", buf, sizeof(buf)) > 0 )
		if( !strcmp(buf, type) )
			if( (*icount)++ == index )
				return ph;
	if( (ph2=prom_find_device_type_( prom_peer(ph), type, icount, index )) != -1 )
		return ph2;
	if( (ph2=prom_find_device_type_( prom_child(ph), type, icount, index )) != -1 )
		return ph2;
	return -1;
}

mol_phandle_t
prom_find_device_type( const char *type, int index )
{
	int count = 0;
	return prom_find_device_type_( prom_peer(0), type, &count, index );
}


/************************************************************************/
/*	device tree tweaking						*/
/************************************************************************/

/* -1 if error */
int
prom_change_phandle( mol_phandle_t old_ph, mol_phandle_t new_ph )
{
	return OSI_PromIface1( kPromChangePHandle, old_ph, (int)new_ph );
}
