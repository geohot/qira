/*
 *   Creation Date: <2003/11/18 14:55:05 samuel>
 *   Time-stamp: <2004/03/27 02:03:55 samuel>
 *
 *	<tree.c>
 *
 *	device tree setup
 *
 *   Copyright (C) 2003, 2004 Samuel Rydh (samuel@ibrium.se)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   version 2
 *
 */

#include "config.h"
#include "libopenbios/bindings.h"
#include "mol/mol.h"
#include "mol/prom.h"


/************************************************************************/
/*	copy device tree						*/
/************************************************************************/

static void
copy_node( mol_phandle_t molph )
{
	char name[40], path[80];
	int exists;
	phandle_t ph;

	if( !molph )
		return;

	prom_package_to_path( molph, path, sizeof(path) );

	/* don't copy /options node */
	if( !strcmp("/options", path) ) {
		copy_node( prom_peer(molph) );
		return;
	}

	exists = 1;
	if( !(ph=find_dev(path)) ) {
		exists = 0;
		fword("new-device");
		ph = get_cur_dev();
	}
	activate_dev( ph );

	name[0] = 0;
	while( prom_next_prop(molph, name, name) > 0 ) {
		int len = prom_get_prop_len( molph, name );
		char *p;
#if 0
		if( len > 0x1000 ) {
			printk("prop to large (%d)\n", len );
			continue;
		}
#endif
		/* don't copy /chosen/{stdin,stdout} (XXX: ugly hack...) */
		if( !strcmp("/chosen", path) )
			if( !strcmp("stdio", name) || !strcmp("stdout", name) )
				continue;

		p = malloc( len );
		prom_get_prop( molph, name, p, len );
		set_property( ph, name, p, len );
		free( p );
	}

	set_int_property( ph, "MOL,phandle", molph );
	copy_node( prom_child(molph) );

	if( !exists )
		fword("finish-device");
	else
		activate_device("..");

	copy_node( prom_peer(molph) );
}



/************************************************************************/
/*	device tree cloning and tweaking				*/
/************************************************************************/

static phandle_t
translate_molph( mol_phandle_t molph )
{
	static mol_phandle_t cached_molph;
	static phandle_t cached_ph;
	phandle_t ph=0;

	if( cached_molph == molph )
		return cached_ph;

	while( (ph=dt_iterate(ph)) )
		if( get_int_property(ph, "MOL,phandle", NULL) == molph )
			break;
	cached_molph = molph;
	cached_ph = ph;

	if( !ph )
		printk("failed to translate molph\n");
	return ph;
}

static void
fix_phandles( void )
{
	static char *pnames[] = { "interrupt-parent", "interrupt-controller", NULL } ;
	int len, *map;
	phandle_t ph=0;
	char **pp;

	while( (ph=dt_iterate(ph)) ) {
		for( pp=pnames; *pp; pp++ ) {
			phandle_t *p = (phandle_t*)get_property( ph, *pp, &len );
			if( len == 4 )
				*p = translate_molph( *(int*)p );
		}

		/* need to fix interrupt map properties too */
		if( (map=(int*)get_property(ph, "interrupt-map", &len)) ) {
			int i, acells = get_int_property(ph, "#address-cells", NULL);
			int icells = get_int_property(ph, "#interrupt-cells", NULL);

			len /= sizeof(int);
			for( i=0; i<len; i++ ) {
				phandle_t ch_ph;
				int ch_acells, ch_icells;

				i += acells + icells;
				if( !(ch_ph=translate_molph(map[i])) )
					break;
				map[i] = (int)ch_ph;
				ch_acells = get_int_property(ch_ph, "#address-cells", NULL);
				ch_icells = get_int_property(ch_ph, "#interrupt-cells", NULL);
				i += ch_acells + icells;
			}
			if( i != len )
				printk("interrupt map fixing failure\n");
		}
	}
	/* delete MOL,phandle properties */
	for( ph=0; (ph=dt_iterate(ph)) ; ) {
		push_str("MOL,phandle");
		PUSH_ph(ph);
		fword("(delete-property)");
	}
	fword("device-end");
}

void
devtree_init( void )
{
	activate_device("/");
	copy_node( prom_peer(0) );
	fix_phandles();
	fword("tree-fixes");
}
