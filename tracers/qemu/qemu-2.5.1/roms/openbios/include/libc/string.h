/*
 *   Creation Date: <2002/10/12 20:41:57 samuel>
 *   Time-stamp: <2003/10/25 12:51:22 samuel>
 *
 *	<string.h>
 *
 *	string library functions
 *
 *   Copyright (C) 2002, 2003 Samuel Rydh (samuel@ibrium.se)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation
 *
 */

#ifndef _H_STRING
#define _H_STRING

#include "config.h"

#define bzero(s,n)	memset( s, 0, n )
#define atol(nptr)	strtol(nptr, NULL, 10 )

extern long	strtol( const char *nptr, char **endptr, int base );
extern long long int strtoll( const char *nptr, char **endptr, int base );


extern int 	strnicmp(const char *s1, const char *s2, size_t len);
extern char 	*strcpy(char * dest,const char *src);
extern char 	*strncpy(char * dest,const char *src,size_t count);
extern char 	*strcat(char * dest, const char * src);
extern char 	*strncat(char *dest, const char *src, size_t count);
extern int 	strcmp(const char * cs,const char * ct);
extern int 	strncmp(const char * cs,const char * ct,size_t count);
extern char 	*strchr(const char * s, int c);
extern char 	*strrchr(const char * s, int c);
extern size_t	strlen(const char * s);
extern size_t	strnlen(const char * s, size_t count);
extern char 	*strpbrk(const char * cs,const char * ct);
extern char 	*strsep(char **s, const char *ct);
extern void	*memset(void * s,int c,size_t count);
extern void 	*memcpy(void * dest,const void *src,size_t count);
extern void 	*memmove(void * dest,const void *src,size_t count);
extern int	memcmp(const void * cs,const void * ct,size_t count);

extern char	*strdup( const char *str );
extern int	strcasecmp( const char *cs, const char *ct );
extern int	strncasecmp( const char *cs, const char *ct, size_t count );

extern  char 	*strncpy_nopad( char *dest, const char *src, size_t n );

#define _U      0x01    /* upper */
#define _L      0x02    /* lower */
#define _D      0x04    /* digit */
#define _C      0x08    /* cntrl */
#define _P      0x10    /* punct */
#define _S      0x20    /* white space (space/lf/tab) */
#define _X      0x40    /* hex digit */
#define _SP     0x80    /* hard space (0x20) */

extern const unsigned char _ctype[];

#define __ismask(x) (_ctype[(int)(unsigned char)(x)])

#define isalnum(c)      ((__ismask(c)&(_U|_L|_D)) != 0)
#define isalpha(c)      ((__ismask(c)&(_U|_L)) != 0)
#define iscntrl(c)      ((__ismask(c)&(_C)) != 0)
#define isdigit(c)      ((__ismask(c)&(_D)) != 0)
#define isgraph(c)      ((__ismask(c)&(_P|_U|_L|_D)) != 0)
#define islower(c)      ((__ismask(c)&(_L)) != 0)
#define isprint(c)      ((__ismask(c)&(_P|_U|_L|_D|_SP)) != 0)
#define ispunct(c)      ((__ismask(c)&(_P)) != 0)
#define isspace(c)      ((__ismask(c)&(_S)) != 0)
#define isupper(c)      ((__ismask(c)&(_U)) != 0)
#define isxdigit(c)     ((__ismask(c)&(_D|_X)) != 0)

#define isascii(c) (((unsigned char)(c))<=0x7f)
#define toascii(c) (((unsigned char)(c))&0x7f)


static inline unsigned char __tolower(unsigned char c) {
        if (isupper(c))
                c -= 'A'-'a';
        return c;
}

static inline unsigned char __toupper(unsigned char c) {
        if (islower(c))
                c -= 'a'-'A';
        return c;
}

#define tolower(c) __tolower(c)
#define toupper(c) __toupper(c)

extern int errno_int;

// Propolice support
extern long __guard[8];

void __stack_smash_handler(const char *func, int damaged);
void __stack_chk_fail(void);

#endif   /* _H_STRING */
