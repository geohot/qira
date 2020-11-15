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

#include "stdio.h"
#include "stdlib.h"
#include "string.h"


static void
_scanf(const char **buffer, const char *fmt, va_list *ap)
{
	int i;
	int length = 0;

	fmt++;	

	while(*fmt != '\0') {
		
		char tbuf[256];

		switch(*fmt) {
			case 'd':
			case 'i':
				if(length == 0) length = 256;
				
				for(i = 0; **buffer != ' ' && **buffer != '\t' && **buffer != '\n' && i < length; i++) {
					tbuf[i] = **buffer;
					*buffer += 1;
				}
				tbuf[i] = '\0';

				*(va_arg(*ap, int *)) = strtol(tbuf, NULL, 10);
				break;
			case 'X':
			case 'x':
				if(length == 0) length = 256;
				
				for(i = 0; **buffer != ' ' && **buffer != '\t' && **buffer != '\n' && i < length; i++) {
					tbuf[i] = **buffer;
					*buffer += 1;
				}
				tbuf[i] = '\0';
					
				*(va_arg(*ap, int *)) = strtol(tbuf, NULL, 16);
				break;
			case 'O':
			case 'o':
				if(length == 0) length = 256;
				
				for(i = 0; **buffer != ' ' && **buffer != '\t' && **buffer != '\n' && i < length; i++) {
					tbuf[i] = **buffer;
					*buffer += 1;
				}
				tbuf[i] = '\0';

				*(va_arg(*ap, int *)) = strtol(tbuf, NULL, 8);
				break;
			case 'c':
				*(va_arg(*ap, char *)) = **buffer;
				*buffer += 1;
				if(length > 1)
					for(i = 1; i < length; i++)
						*buffer += 1;
				break;
			case 's':
				if(length == 0) length = 256;
				
				for(i = 0; **buffer != ' ' && **buffer != '\t' && **buffer != '\n' && i < length; i++) {
					tbuf[i] = **buffer;
					*buffer += 1;
				}

				tbuf[i] = '\0';

				strcpy(va_arg(*ap, char *), tbuf);
				break;
			default:
				if(*fmt >= '0' && *fmt <= '9') 
					length += *fmt - '0';
				break;
		}
		fmt++;
	}

}


int
vsscanf(const char *buffer, const char *fmt, va_list ap)
{

	while(*fmt != '\0') {
		
		if(*fmt == '%') {
			
			char formstr[20];
			int i=0;
			
			do {
				formstr[i] = *fmt;
				fmt++;
				i++;
			} while(!(*fmt == 'd' || *fmt == 'i' || *fmt == 'x' || *fmt == 'X'
						|| *fmt == 'p' || *fmt == 'c' || *fmt == 's' || *fmt == '%'
						|| *fmt == 'O' || *fmt == 'o' )); 
			formstr[i++] = *fmt;
			formstr[i] = '\0';
			if(*fmt != '%') {
				while(*buffer == ' ' || *buffer == '\t' || *buffer == '\n')
					buffer++;
				_scanf(&buffer, formstr, &ap);
			}

		} 

		fmt++;

	}

	return 0;
}

