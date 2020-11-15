/*
 * Copyright (C) 2006 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * You can also choose to distribute this program under the terms of
 * the Unmodified Binary Distribution Licence (as given in the file
 * COPYING.UBDL), provided that you have satisfied its requirements.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <string.h>
#include <assert.h>
#include <ipxe/ansiesc.h>

/** @file
 *
 * ANSI escape sequences
 *
 */

/**
 * Call ANSI escape sequence handler
 *
 * @v ctx		ANSI escape sequence context
 * @v function		Control function identifier
 * @v count		Parameter count
 * @v params		Parameter list
 */
static void ansiesc_call_handler ( struct ansiesc_context *ctx,
				   unsigned int function, int count,
				   int params[] ) {
	struct ansiesc_handler *handlers = ctx->handlers;
	struct ansiesc_handler *handler;

	for ( handler = handlers ; handler->function ; handler++ ) {
		if ( handler->function == function ) {
			handler->handle ( ctx, count, params );
			break;
		}
	}
}

/**
 * Process character that may be part of ANSI escape sequence
 *
 * @v ctx		ANSI escape sequence context
 * @v c			Character
 * @ret c		Original character if not part of escape sequence
 * @ret <0		Character was part of escape sequence
 *
 * ANSI escape sequences will be plucked out of the character stream
 * and interpreted; once complete they will be passed to the
 * appropriate handler if one exists in this ANSI escape sequence
 * context.
 *
 * In the interests of code size, we are rather liberal about the
 * sequences we are prepared to accept as valid.
 */
int ansiesc_process ( struct ansiesc_context *ctx, int c ) {

	if ( ctx->count == 0 ) {
		if ( c == ESC ) {
			/* First byte of CSI : begin escape sequence */
			ctx->count = 1;
			memset ( ctx->params, 0xff, sizeof ( ctx->params ) );
			ctx->function = 0;
			return -1;
		} else {
			/* Normal character */
			return c;
		}
	} else {
		if ( c == '[' ) {
			/* Second byte of CSI : do nothing */
		} else if ( ( c >= '0' ) && ( c <= '9' ) ) {
			/* Parameter Byte : part of a parameter value */
			int *param = &ctx->params[ctx->count - 1];
			if ( *param < 0 )
				*param = 0;
			*param = ( ( *param * 10 ) + ( c - '0' ) );
		} else if ( c == ';' ) {
			/* Parameter Byte : parameter delimiter */
			ctx->count++;
			if ( ctx->count > ( sizeof ( ctx->params ) /
					    sizeof ( ctx->params[0] ) ) ) {
				/* Excessive parameters : abort sequence */
				ctx->count = 0;
				DBG ( "Too many parameters in ANSI escape "
				      "sequence\n" );
			}
		} else if ( ( ( c >= 0x20 ) && ( c <= 0x2f ) ) ||
			    ( c == '?' ) ) {
			/* Intermediate Byte */
			ctx->function <<= 8;
			ctx->function |= c;
		} else {
			/* Treat as Final Byte.  Zero ctx->count before 
			 * calling handler to avoid potential infinite loops.
			 */
			int count = ctx->count;
			ctx->count = 0;
			ctx->function <<= 8;
			ctx->function |= c;
			ansiesc_call_handler ( ctx, ctx->function,
					       count, ctx->params );
		}
		return -1;
	}
}
