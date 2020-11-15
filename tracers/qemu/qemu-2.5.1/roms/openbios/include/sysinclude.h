#ifndef __SYSINCLUDE_H
#define __SYSINCLUDE_H

#ifdef BOOTSTRAP
#include "asm/types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#else /* BOOTSTRAP */
#include "libc/stdlib.h"
#include "libc/string.h"
#endif /* BOOTSTRAP */

extern int	printk( const char *fmt, ... ) \
			__attribute__ ((format (printf, 1, 2)));
#ifdef BOOTSTRAP
#define printk printf
#endif

#endif   /* __SYSINCLUDE_H */
