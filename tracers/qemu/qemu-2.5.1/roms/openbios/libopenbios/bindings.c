/*
 *   Creation Date: <2003/11/24 12:30:18 samuel>
 *   Time-stamp: <2004/01/07 19:37:38 samuel>
 *
 *	<bindings.c>
 *
 *	Forth bindings
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
#include "libc/string.h"
#include "libc/stdlib.h"
#include "libc/byteorder.h"


/************************************************************************/
/*	forth interface glue						*/
/************************************************************************/

void
push_str( const char *str )
{
	PUSH( pointer2cell(str) );
	PUSH( str ? strlen(str) : 0 );
}

/* WARNING: sloooow - AVOID */
cell
feval( const char *str )
{
	push_str( str );
	return eword("evaluate", 2);
}

cell
_eword( const char *word, xt_t *cache_xt, int nargs )
{
	static xt_t catch_xt = 0;
	cell ret = -1;

	if( !catch_xt )
		catch_xt = findword("catch");
	if( !*cache_xt )
		*cache_xt = findword( (char*)word );

	if( *cache_xt ) {
		PUSH_xt( *cache_xt );
		enterforth( catch_xt );
		if( (ret=POP()) )
			dstackcnt -= nargs;
	}
	return ret;
}

/* note: only the built-in dictionary is searched */
int
_fword( const char *word, xt_t *cache_xt )
{
	if( !*cache_xt )
		*cache_xt = findword( (char*)word );

	if( *cache_xt ) {
		enterforth( *cache_xt );
		return 0;
	}
	return -1;
}

int
_selfword( const char *method, xt_t *cache_xt )
{
	if( !*cache_xt )
		*cache_xt = find_ih_method( method, my_self() );
	if( *cache_xt ) {
		enterforth( *cache_xt );
		return 0;
	}
	return -1;
}

int
_parword( const char *method, xt_t *cache_xt )
{
	if( !*cache_xt )
		*cache_xt = find_ih_method( method, my_parent() );
	if( *cache_xt ) {
		enterforth( *cache_xt );
		return 0;
	}
	return -1;
}

void
bind_func( const char *name, void (*func)(void) )
{
	PUSH( pointer2cell(func) );
	push_str( name );
	fword("is-cfunc");
}

void
bind_xtfunc( const char *name, xt_t xt, ucell arg, void (*func)(void) )
{
	PUSH_xt( xt );
	PUSH( arg );
	PUSH( pointer2cell(func) );
	push_str( name );
	fword("is-xt-cfunc");
}

xt_t
bind_noname_func( void (*func)(void) )
{
	PUSH( pointer2cell(func) );
	fword("is-noname-cfunc");
	return POP_xt();
}

void
throw( int error )
{
	PUSH( error );
	fword("throw");
}


/************************************************************************/
/*	ihandle related							*/
/************************************************************************/

phandle_t
ih_to_phandle( ihandle_t ih )
{
	PUSH_ih( ih );
	fword("ihandle>phandle");
	return POP_ph();
}

ihandle_t
my_parent( void )
{
	fword("my-parent");
	return POP_ih();
}

ihandle_t
my_self( void )
{
	fword("my-self");
	return POP_ih();
}

xt_t
find_package_method( const char *method, phandle_t ph )
{
	push_str( method );
	PUSH_ph( ph );
	fword("find-method");
	if( POP() )
		return POP_xt();
	return 0;
}

xt_t
find_ih_method( const char *method, ihandle_t ih )
{
	return find_package_method( method, ih_to_phandle(ih) );
}


xt_t
find_parent_method( const char *method )
{
	return find_ih_method( method, my_parent() );
}

void
call_package( xt_t xt, ihandle_t ihandle )
{
	PUSH_xt( xt );
	PUSH_ih( ihandle );
	fword("call-package");
}

void
call_parent( xt_t xt )
{
	PUSH_xt( xt );
	fword("call-parent");
}

void
call_parent_method( const char *method )
{
	push_str( method );
	fword("$call-parent");
}


/************************************************************************/
/*	open/close package/dev						*/
/************************************************************************/

ihandle_t
open_dev( const char *spec )
{
	push_str( spec );
	fword("open-dev");
	return POP_ih();
}

void
close_dev( ihandle_t ih )
{
	PUSH_ih( ih );
	fword("close-dev");
}

ihandle_t
open_package( const char *argstr, phandle_t ph )
{
	push_str( argstr );
	PUSH_ph( ph );
	fword("open-package");
	return POP_ih();
}

void
close_package( ihandle_t ih )
{
	PUSH_ih( ih );
	fword("close-package");
}


/************************************************************************/
/*	ihandle arguments						*/
/************************************************************************/

char *
pop_fstr_copy( void )
{
	int len = POP();
	char *str, *p = (char*)cell2pointer(POP());
	if( !len )
		return NULL;
	str = malloc( len + 1 );
        if( !str )
                return NULL;
	memcpy( str, p, len );
	str[len] = 0;
	return str;
}

char *
my_args_copy( void )
{
	fword("my-args");
	return pop_fstr_copy();
}


/************************************************************************/
/*	properties							*/
/************************************************************************/

void
set_property( phandle_t ph, const char *name, const char *buf, int len )
{
	if( !ph ) {
		printk("set_property: NULL phandle\n");
		return;
	}
	PUSH(pointer2cell(buf));
	PUSH(len);
	push_str( name );
	PUSH_ph(ph);
	fword("set-property");
}

void
set_int_property( phandle_t ph, const char *name, u32 val )
{
	u32 swapped=__cpu_to_be32(val);
	set_property( ph, name, (char*)&swapped, sizeof(swapped) );
}

char *
get_property( phandle_t ph, const char *name, int *retlen )
{
	int len;

	if( retlen )
		*retlen = -1;

	push_str( name );
	PUSH_ph( ph );
	fword("get-package-property");
	if( POP() )
		return NULL;
	len = POP();
	if( retlen )
		*retlen = len;
	return (char*)cell2pointer(POP());
}

u32
get_int_property( phandle_t ph, const char *name, int *retlen )
{
	u32 *p;

	if( !(p=(u32 *)get_property(ph, name, retlen)) )
		return 0;
	return __be32_to_cpu(*p);
}


/************************************************************************/
/*	device selection / iteration					*/
/************************************************************************/

void
activate_dev( phandle_t ph )
{
	PUSH_ph( ph );
	fword("active-package!");
}

phandle_t
activate_device( const char *str )
{
	phandle_t ph = find_dev( str );
	activate_dev( ph );
	return ph;
}

void
device_end( void )
{
	fword("device-end");
}

phandle_t
get_cur_dev( void )
{
	fword("active-package");
	return POP_ph();
}

phandle_t
find_dev( const char *path )
{
	phandle_t ret = 0;
	push_str( path );
	fword("(find-dev)");
	if( POP() )
		return POP_ph();
	return ret;
}

phandle_t
dt_iter_begin( void )
{
	fword("iterate-tree-begin");
	return POP_ph();
}

phandle_t
dt_iterate( phandle_t last_tree )
{
        if( !last_tree )
		return dt_iter_begin();

        PUSH_ph( last_tree );
	fword("iterate-tree");
	return POP_ph();
}

phandle_t
dt_iterate_type( phandle_t last_tree, const char *type )
{
        if( !last_tree )
                last_tree = dt_iter_begin();

	/* root node is never matched but we don't care about that */
        while( (last_tree = dt_iterate(last_tree)) ) {
                char *s = get_property( last_tree, "device_type", NULL );
		if( s && !strcmp(type, s) )
			break;
	}
        return last_tree;
}


/************************************************************************/
/*	node methods							*/
/************************************************************************/

void
make_openable( int only_parents )
{
	phandle_t ph, save_ph = get_cur_dev();
	PUSH_ph( save_ph );

	for( ;; ) {
		if( only_parents++ )
			fword("parent");
		if( !(ph=POP_ph()) )
			break;
		activate_dev( ph );
		PUSH_ph( ph );
		fword("is-open");
	}
	activate_dev( save_ph );
}

static void
call1_func( void )
{
	void (*func)(cell v);
	func = (void*)cell2pointer(POP());

	(*func)( POP() );
}


static void
add_methods( int flags, int size, const method_t *methods, int nmet )
{
	xt_t xt=0;
	int i;

	/* nodes might be matched multiple times */
	if( find_package_method(methods[0].name, get_cur_dev()) )
		return;

	if( size ) {
		PUSH( size );
		fword("is-ibuf");
		xt = POP_xt();
	}

	for( i=0; i<nmet; i++ ) {
		/* null-name methods specify static initializers */
		if( !methods[i].name ) {
			typedef void (*initfunc)( void *p );
			char *buf = NULL;
			if( xt ) {
				enterforth( xt );
				buf = (char*)cell2pointer(POP());
			}
			(*(initfunc)methods[i].func)( buf );
			continue;
		}
		if( !size )
			bind_func( methods[i].name, methods[i].func );
		else
			bind_xtfunc( methods[i].name, xt, pointer2cell(methods[i].func),
				     &call1_func );
	}

	if( flags & INSTALL_OPEN )
		make_openable(0);
}

void
bind_node( int flags, int size, const char * const *paths, int npaths,
	   const method_t *methods, int nmet )
{
	phandle_t save_ph = get_cur_dev();
	int i;

	for( i=0; i<npaths; i++ ) {
		const char *name = paths[i];

		/* type matching? */
		if( *name == 'T' ) {
			phandle_t ph = 0;
			name++;
			while( (ph=dt_iterate_type(ph, name)) ) {
				activate_dev( ph );
				add_methods( flags, size, methods, nmet );
			}
			continue;
		}

		/* path patching */
		if( activate_device(name) )
			add_methods( flags, size, methods, nmet );
		else if( *name == '+' ) {
			/* create node (and missing parents) */
			if( !activate_device(++name) ) {
				push_str( name );
				fword("create-node");
			}
			add_methods( flags, size, methods, nmet );
		}
	}
	activate_dev( save_ph );
}

phandle_t
bind_new_node( int flags, int size, const char *name,
	   const method_t *methods, int nmet )
{
	phandle_t save_ph = get_cur_dev();
	phandle_t new_ph;
	/* create node */
	push_str( name );
	fword("create-node");
	add_methods( flags, size, methods, nmet );
    new_ph = get_cur_dev();

	activate_dev( save_ph );
	return new_ph;
}
