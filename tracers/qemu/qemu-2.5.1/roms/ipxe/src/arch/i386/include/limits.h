#ifndef LIMITS_H
#define LIMITS_H	1

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/* Number of bits in a `char' */
#define CHAR_BIT	8

/* Minimum and maximum values a `signed char' can hold */
#define SCHAR_MIN	(-128)
#define SCHAR_MAX	127

/* Maximum value an `unsigned char' can hold. (Minimum is 0.) */
#define UCHAR_MAX	255

/* Minimum and maximum values a `char' can hold */
#define CHAR_MIN	SCHAR_MIN
#define CHAR_MAX	SCHAR_MAX

/* Minimum and maximum values a `signed short int' can hold */
#define SHRT_MIN	(-32768)
#define SHRT_MAX	32767

/* Maximum value an `unsigned short' can hold. (Minimum is 0.) */
#define USHRT_MAX	65535


/* Minimum and maximum values a `signed int' can hold */
#define INT_MIN		(-INT_MAX - 1)
#define INT_MAX		2147483647

/* Maximum value an `unsigned int' can hold. (Minimum is 0.) */
#define UINT_MAX	4294967295U


/* Minimum and maximum values a `signed int' can hold */
#define INT_MAX		2147483647
#define INT_MIN		(-INT_MAX - 1)


/* Maximum value an `unsigned int' can hold. (Minimum is 0.) */
#define UINT_MAX	4294967295U


/* Minimum and maximum values a `signed long' can hold */
#define LONG_MAX	2147483647
#define LONG_MIN	(-LONG_MAX - 1L)

/* Maximum value an `unsigned long' can hold. (Minimum is 0.) */
#define ULONG_MAX	4294967295UL

/* Minimum and maximum values a `signed long long' can hold */
#define LLONG_MAX	9223372036854775807LL
#define LLONG_MIN	(-LONG_MAX - 1LL)


/* Maximum value an `unsigned long long' can hold. (Minimum is 0.) */
#define ULLONG_MAX	18446744073709551615ULL


#endif /* LIMITS_H */
