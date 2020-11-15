#ifndef _STDARG_H
#define _STDARG_H

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

typedef __builtin_va_list va_list;
#define va_start( ap, last ) __builtin_va_start ( ap, last )
#define va_arg( ap, type ) __builtin_va_arg ( ap, type )
#define va_end( ap ) __builtin_va_end ( ap )
#define va_copy( dest, src ) __builtin_va_copy ( dest, src )

/**
 * Count number of arguments to a variadic macro
 *
 * This rather neat, non-iterative solution is courtesy of Laurent
 * Deniau.
 *
 */
#define _VA_ARG_COUNT(  _1,  _2,  _3,  _4,  _5,  _6,  _7,  _8,		\
		        _9, _10, _11, _12, _13, _14, _15, _16,		\
		       _17, _18, _19, _20, _21, _22, _23, _24,		\
		       _25, _26, _27, _28, _29, _30, _31, _32,		\
		       _33, _34, _35, _36, _37, _38, _39, _40,		\
		       _41, _42, _43, _44, _45, _46, _47, _48,		\
		       _49, _50, _51, _52, _53, _54, _55, _56,		\
		       _57, _58, _59, _60, _61, _62, _63,   N, ... ) N
#define VA_ARG_COUNT( ... )						\
	_VA_ARG_COUNT ( __VA_ARGS__, 					\
			63, 62, 61, 60, 59, 58, 57, 56,			\
			55, 54, 53, 52, 51, 50, 49, 48,			\
			47, 46, 45, 44, 43, 42, 41, 40,			\
			39, 38, 37, 36, 35, 34, 33, 32,			\
			31, 30, 29, 28, 27, 26, 25, 24,			\
			23, 22, 21, 20, 19, 18, 17, 16,			\
			15, 14, 13, 12, 11, 10,  9,  8,			\
			 7,  6,  5,  4,  3,  2,  1,  0 )

#endif /* _STDARG_H */
