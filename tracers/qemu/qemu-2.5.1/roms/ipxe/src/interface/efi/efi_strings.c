/*
 * Copyright (C) 2011 Michael Brown <mbrown@fensystems.co.uk>.
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

#include <stddef.h>
#include <stdarg.h>
#include <ipxe/vsprintf.h>
#include <ipxe/efi/efi_strings.h>

/** Context used by efi_vsnprintf() and friends */
struct efi_sputc_context {
	/** printf context */
	struct printf_context ctx;
	/** Buffer for formatted string (used by efi_printf_sputc()) */
	wchar_t *buf;
	/** Buffer length (used by efi_printf_sputc())
	 *
	 * Note that this is a number of wide characters, not a number
	 * of bytes.
	 */
	size_t max_wlen;
};

/**
 * Write wide character to buffer
 *
 * @v ctx		Context
 * @v c			Character
 */
static void efi_printf_sputc ( struct printf_context *ctx, unsigned int c ) {
	struct efi_sputc_context * sctx =
		container_of ( ctx, struct efi_sputc_context, ctx );

	if ( ctx->len < sctx->max_wlen )
		sctx->buf[ctx->len] = c;
}

/**
 * Write a formatted string to a wide-character buffer
 *
 * @v wbuf		Buffer into which to write the string
 * @v wsize		Size of buffer (in wide characters)
 * @v fmt		Format string
 * @v args		Arguments corresponding to the format string
 * @ret wlen		Length of formatted string (in wide characters)
 *
 * If the buffer is too small to contain the string, the returned
 * length is the length that would have been written had enough space
 * been available.
 */
int efi_vsnprintf ( wchar_t *wbuf, size_t wsize, const char *fmt,
		    va_list args ) {
	struct efi_sputc_context sctx;
	size_t wlen;
	size_t wend;

	/* Hand off to vcprintf */
	sctx.ctx.handler = efi_printf_sputc;
	sctx.buf = wbuf;
	sctx.max_wlen = wsize;
	wlen = vcprintf ( &sctx.ctx, fmt, args );

	/* Add trailing NUL */
	if ( wsize ) {
		wend = wsize - 1;
		if ( wlen < wend )
			wend = wlen;
		wbuf[wend] = '\0';
	}

	return wlen;
}

/**
 * Write a formatted string to a buffer
 *
 * @v wbuf		Buffer into which to write the string
 * @v wsize		Size of buffer (in wide characters)
 * @v fmt		Format string
 * @v ...		Arguments corresponding to the format string
 * @ret wlen		Length of formatted string (in wide characters)
 */
int efi_snprintf ( wchar_t *wbuf, size_t wsize, const char *fmt, ... ) {
	va_list args;
	int i;

	va_start ( args, fmt );
	i = efi_vsnprintf ( wbuf, wsize, fmt, args );
	va_end ( args );
	return i;
}

/**
 * Version of efi_vsnprintf() that accepts a signed buffer size
 *
 * @v wbuf		Buffer into which to write the string
 * @v swsize		Size of buffer (in wide characters)
 * @v fmt		Format string
 * @v args		Arguments corresponding to the format string
 * @ret wlen		Length of formatted string (in wide characters)
 */
int efi_vssnprintf ( wchar_t *wbuf, ssize_t swsize, const char *fmt,
		     va_list args ) {

	/* Treat negative buffer size as zero buffer size */
	if ( swsize < 0 )
		swsize = 0;

	/* Hand off to vsnprintf */
	return efi_vsnprintf ( wbuf, swsize, fmt, args );
}

/**
 * Version of efi_vsnprintf() that accepts a signed buffer size
 *
 * @v wbuf		Buffer into which to write the string
 * @v swsize		Size of buffer (in wide characters)
 * @v fmt		Format string
 * @v ...		Arguments corresponding to the format string
 * @ret wlen		Length of formatted string (in wide characters)
 */
int efi_ssnprintf ( wchar_t *wbuf, ssize_t swsize, const char *fmt, ... ) {
	va_list args;
	int len;

	/* Hand off to vssnprintf */
	va_start ( args, fmt );
	len = efi_vssnprintf ( wbuf, swsize, fmt, args );
	va_end ( args );
	return len;
}
