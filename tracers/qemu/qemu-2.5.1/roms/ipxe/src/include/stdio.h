#ifndef _STDIO_H
#define _STDIO_H

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <stdarg.h>

extern void putchar ( int character );

extern int getchar ( void );

extern int __attribute__ (( format ( printf, 1, 2 ) ))
printf ( const char *fmt, ... );

extern int __attribute__ (( format ( printf, 3, 4 ) ))
snprintf ( char *buf, size_t size, const char *fmt, ... );

extern int __attribute__ (( format ( printf, 2, 3 ) ))
asprintf ( char **strp, const char *fmt, ... );

extern int vprintf ( const char *fmt, va_list args );

extern int vsnprintf ( char *buf, size_t size, const char *fmt, va_list args );

extern int vasprintf ( char **strp, const char *fmt, va_list args );

/**
 * Write a formatted string to a buffer
 *
 * @v buf		Buffer into which to write the string
 * @v fmt		Format string
 * @v ...		Arguments corresponding to the format string
 * @ret len		Length of formatted string
 */
#define sprintf( buf, fmt, ... ) \
	snprintf ( (buf), ~( ( size_t ) 0 ), (fmt), ## __VA_ARGS__ )

/**
 * Write a formatted string to a buffer
 *
 * @v buf		Buffer into which to write the string
 * @v fmt		Format string
 * @v args		Arguments corresponding to the format string
 * @ret len		Length of formatted string
 */
static inline int vsprintf ( char *buf, const char *fmt, va_list args ) {
	return vsnprintf ( buf, ~( ( size_t ) 0 ), fmt, args );
}

#endif /* _STDIO_H */
