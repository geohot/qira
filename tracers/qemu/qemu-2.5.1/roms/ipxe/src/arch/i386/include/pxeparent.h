#ifndef PXEPARENT_H
#define PXEPARENT_H

FILE_LICENCE ( GPL2_OR_LATER );

#include <pxe_types.h>

extern int pxeparent_call ( SEGOFF16_t entry, unsigned int function,
			    void *params, size_t params_len );

#endif
