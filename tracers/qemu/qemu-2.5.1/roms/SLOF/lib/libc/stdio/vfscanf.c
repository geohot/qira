/******************************************************************************
 * Copyright (c) 2004, 2008 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/

#include "string.h"
#include "ctype.h"
#include "stdlib.h"
#include "stdio.h"
#include "unistd.h"


static int
_getc(FILE * stream)
{
	int count;
	char c;

	if (stream->mode == _IONBF || stream->buf == NULL) {
		if (read(stream->fd, &c, 1) == 1)
			return (int) c;
		else
			return EOF;
	}

	if (stream->pos == 0 || stream->pos >= BUFSIZ ||
	    stream->buf[stream->pos] == '\0') {
		count = read(stream->fd, stream->buf, BUFSIZ);
		if (count < 0)
			count = 0;
		if (count < BUFSIZ)
			stream->buf[count] = '\0';
		stream->pos = 0;
	}

	return stream->buf[stream->pos++];
}

static void
_ungetc(int ch, FILE * stream)
{
	if (stream->mode != _IONBF && stream->pos > 0)
		stream->pos--;
}

static int
_is_voidage(int ch)
{
	if (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' || ch == '\0')
		return 1;
	else
		return 0;
}


static int
_scanf(FILE * stream, const char *fmt, va_list * ap)
{
	int i = 0;
	int length = 0;

	fmt++;

	while (*fmt != '\0') {

		char tbuf[256];
		char ch;

		switch (*fmt) {
		case 'd':
		case 'i':
			ch = _getc(stream);
			if (length == 0) {
				while (!_is_voidage(ch) && isdigit(ch)) {
					tbuf[i] = ch;
					ch = _getc(stream);
					i++;
				}
			} else {
				while (!_is_voidage(ch) && i < length
				       && isdigit(ch)) {
					tbuf[i] = ch;
					ch = _getc(stream);
					i++;
				}
			}
			/* We tried to understand what this is good for...
			 * but we did not. We know for sure that it does not
			 * work on SLOF if this is active. */
			/* _ungetc(ch, stream); */
			tbuf[i] = '\0';

			/* ch = _getc(stream); */
			if (!_is_voidage(ch))
				_ungetc(ch, stream);

			if (strlen(tbuf) == 0)
				return 0;

			*(va_arg(*ap, int *)) = strtol(tbuf, NULL, 10);
			break;
		case 'X':
		case 'x':
			ch = _getc(stream);
			if (length == 0) {
				while (!_is_voidage(ch) && isxdigit(ch)) {
					tbuf[i] = ch;
					ch = _getc(stream);
					i++;
				}
			} else {
				while (!_is_voidage(ch) && i < length
				       && isxdigit(ch)) {
					tbuf[i] = ch;
					ch = _getc(stream);
					i++;
				}
			}
			/* _ungetc(ch, stream); */
			tbuf[i] = '\0';

			/* ch = _getc(stream); */
			if (!_is_voidage(ch))
				_ungetc(ch, stream);

			if (strlen(tbuf) == 0)
				return 0;

			*(va_arg(*ap, int *)) = strtol(tbuf, NULL, 16);
			break;
		case 'O':
		case 'o':
			ch = _getc(stream);
			if (length == 0) {
				while (!_is_voidage(ch)
				       && !(ch < '0' || ch > '7')) {
					tbuf[i] = ch;
					ch = _getc(stream);
					i++;
				}
			} else {
				while (!_is_voidage(ch) && i < length
				       && !(ch < '0' || ch > '7')) {
					tbuf[i] = ch;
					ch = _getc(stream);
					i++;
				}
			}
			/* _ungetc(ch, stream); */
			tbuf[i] = '\0';

			/* ch = _getc(stream); */
			if (!_is_voidage(ch))
				_ungetc(ch, stream);

			if (strlen(tbuf) == 0)
				return 0;

			*(va_arg(*ap, int *)) = strtol(tbuf, NULL, 8);
			break;
		case 'c':
			ch = _getc(stream);
			while (_is_voidage(ch))
				ch = _getc(stream);

			*(va_arg(*ap, char *)) = ch;

			ch = _getc(stream);
			if (!_is_voidage(ch))
				_ungetc(ch, stream);

			break;
		case 's':
			ch = _getc(stream);
			if (length == 0) {
				while (!_is_voidage(ch)) {
					tbuf[i] = ch;
					ch = _getc(stream);
					i++;
				}
			} else {
				while (!_is_voidage(ch) && i < length) {
					tbuf[i] = ch;
					ch = _getc(stream);
					i++;
				}
			}
			/* _ungetc(ch, stream); */
			tbuf[i] = '\0';

			/* ch = _getc(stream); */
			if (!_is_voidage(ch))
				_ungetc(ch, stream);

			strcpy(va_arg(*ap, char *), tbuf);
			break;
		default:
			if (*fmt >= '0' && *fmt <= '9')
				length += *fmt - '0';
			break;
		}
		fmt++;
	}

	return 1;
}



int
vfscanf(FILE * stream, const char *fmt, va_list ap)
{
	int args = 0;

	while (*fmt != '\0') {

		if (*fmt == '%') {

			char formstr[20];
			int i = 0;

			do {
				formstr[i] = *fmt;
				fmt++;
				i++;
			} while (!
				 (*fmt == 'd' || *fmt == 'i' || *fmt == 'x'
				  || *fmt == 'X' || *fmt == 'p' || *fmt == 'c'
				  || *fmt == 's' || *fmt == '%' || *fmt == 'O'
				  || *fmt == 'o'));
			formstr[i++] = *fmt;
			formstr[i] = '\0';
			if (*fmt != '%') {
				if (_scanf(stream, formstr, &ap) <= 0)
					return args;
				else
					args++;
			}

		}

		fmt++;

	}

	return args;
}

int
getc(FILE * stream)
{
	return _getc(stream);
}

int
getchar(void)
{
	return _getc(stdin);
}
