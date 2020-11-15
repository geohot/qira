/*
 *   Creation Date: <2003/12/19 23:09:56 samuel>
 *   Time-stamp: <2004/01/07 19:36:42 samuel>
 *
 *	<bindings.h>
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

#ifndef _H_BINDINGS
#define _H_BINDINGS

#include "kernel/stack.h"
#include "kernel/kernel.h"

#define PUSH3(a,b,c)	do { PUSH((a)); PUSH((b)); PUSH((c)); } while(0)
#define PUSH2(a,b)	do { PUSH((a)); PUSH((b)); } while(0)
#define RET( v )	do { PUSH(v); return; } while(0)

/* initialization */
extern int		initialize_forth( void );

/* panic */
extern int		forth_segv_handler( char *segv_addr );

/* active package */
extern phandle_t	find_dev( const char *path );
extern phandle_t	get_cur_dev( void );
extern phandle_t	activate_device( const char *str );
extern void		device_end( void );
extern void		activate_dev( phandle_t ph );


/* ihandle related */
extern phandle_t	ih_to_phandle( ihandle_t ih );
extern ihandle_t	my_parent( void );
extern ihandle_t	my_self( void );
extern char		*my_args_copy( void );

extern xt_t		find_package_method( const char *meth, phandle_t ph );
extern xt_t		find_ih_method( const char *method, ihandle_t ih );
extern xt_t		find_parent_method( const char *method );
extern void		call_package( xt_t xt, ihandle_t ihandle );
extern void		call_parent( xt_t xt );
extern void		call_parent_method( const char *method );

/* package */
extern ihandle_t	open_package( const char *argstr, phandle_t ph );
extern ihandle_t	open_dev( const char *spec );
extern void		close_package( ihandle_t ih );
extern void		close_dev( ihandle_t ih );

/* property access */
extern void		set_property( phandle_t ph, const char *name,
				      const char *buf, int len );
extern void		set_int_property( phandle_t ph, const char *name,
					  u32 val );
extern u32		get_int_property( phandle_t ph, const char *name,
					  int *retlen );
extern char		*get_property( phandle_t ph, const char *name,
				       int *retlen );

/* device tree iteration */
extern phandle_t	dt_iter_begin( void );
extern phandle_t	dt_iterate( phandle_t last_tree );
extern phandle_t	dt_iterate_type( phandle_t last_tree,
                                         const char *type );
static inline phandle_t dt_find_type( const char *type ) {
	return dt_iterate_type( 0, type );
}

/* forth bindings */
extern cell		feval( const char *str );
extern void		bind_xtfunc( const char *name, xt_t xt,
				     ucell arg, void (*func)(void) );
extern void		bind_func( const char *name, void (*func)(void) );
extern xt_t		bind_noname_func( void (*func)(void) );
extern void		push_str( const char *str );
extern char		*pop_fstr_copy( void );

extern int		_fword( const char *word, xt_t *cache_xt );
extern cell		_eword( const char *word, xt_t *cache_xt, int nargs );
extern int		_selfword( const char *method, xt_t *cache_xt );
extern int		_parword( const char *method, xt_t *cache_xt );

#define fword(w)	({ static xt_t cache_xt = 0; _fword(w, &cache_xt); })
#define eword(w, nargs)	({ static xt_t cache_xt = 0; _eword(w, &cache_xt, nargs); })
#define selfword(w)	({ static xt_t cache_xt = 0; _selfword(w, &cache_xt); })
#define parword(w)	({ static xt_t cache_xt = 0; _parword(w, &cache_xt); })

extern void		throw( int error );


/* node bindings */
extern void		make_openable( int only_parents );


typedef struct {
	const char 	*name;
	void		*func;
} method_t;

#define REGISTER_NAMED_NODE( name, path )   do { \
	bind_new_node( name##_flags_, name##_size_, \
		path, name##_m, sizeof(name##_m)/sizeof(method_t)); \
	} while(0)

#define REGISTER_NAMED_NODE_PHANDLE( name, path, phandle )   do { \
    phandle = \
    bind_new_node( name##_flags_, name##_size_, \
        path, name##_m, sizeof(name##_m)/sizeof(method_t)); \
    } while(0)

#define REGISTER_NODE_METHODS( name, path )   do {			\
	const char *paths[1];						\
									\
	paths[0] = path;						\
	bind_node( name##_flags_, name##_size_,				\
	paths, 1, name##_m, sizeof(name##_m)/sizeof(method_t));		\
    } while(0)

#define DECLARE_UNNAMED_NODE( name, flags, size )	\
static const int name##_flags_ = flags;	\
static const int name##_size_ = size;

#define DECLARE_NODE( name, flags, size, paths... )	\
static const char * const name##_p[] = { paths };	\
DECLARE_UNNAMED_NODE(name, flags, size)

#define NODE_METHODS( name ) \
static const method_t name##_m[]

#define REGISTER_NODE( name )	do { \
	    bind_node( name##_flags_, name##_size_, \
		       name##_p, sizeof(name##_p)/sizeof(char*), \
		       name##_m, sizeof(name##_m)/sizeof(method_t) ); \
        } while(0)

extern void 	bind_node( int flags, int size, const char * const *paths, int npaths,
			   const method_t *methods, int nmethods );

extern phandle_t	bind_new_node( int flags, int size, const char *name,
			   const method_t *methods, int nmethods );

#define INSTALL_OPEN	1	/* install trivial open and close methods */



#endif   /* _H_BINDINGS */
