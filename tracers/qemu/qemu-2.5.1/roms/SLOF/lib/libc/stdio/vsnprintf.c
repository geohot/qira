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

const static unsigned long long convert[] = {
	0x0, 0xFF, 0xFFFF, 0xFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFFFFULL, 0xFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL
};



static int
print_itoa(char **buffer,unsigned long value, unsigned short int base)
{
	const char zeichen[] = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
	static char sign = 0;

	if(base <= 2 || base > 16)
		return 0;

	if(value < 0) {
		sign = 1;
		value *= -1;
	}

	if(value < base) {
		if(sign) {
			**buffer = '-';
			*buffer += 1;
			sign = 0;
		}
		**buffer = zeichen[value];
		*buffer += 1;
	} else {
		print_itoa(buffer, value / base, base);
		**buffer = zeichen[(value % base)];
		*buffer += 1;
	}

	return 1;
}


static unsigned int
print_intlen(unsigned long value, unsigned short int base)
{
	int i = 0;

	while(value > 0) {
		value /= base;
		i++;
	}
	if(i == 0) i = 1;
	return i;
}


static int
print_fill(char **buffer, char *sizec, unsigned long size, unsigned short int base, char c, int optlen)
{
	int i, sizei, len;

	sizei = strtoul(sizec, NULL, 10);
 	len = print_intlen(size, base) + optlen;
	if(sizei > len) {
		for(i = 0; i < (sizei - len); i++) {
			**buffer = c;
			*buffer += 1;
		}
	}

	return 0;
}


static int
print_format(char **buffer, const char *format, void *var)
{
	unsigned long start;
	unsigned int i = 0, sizei = 0, len = 0, length_mod = sizeof(int);
	unsigned long value = 0;
	unsigned long signBit;
	char *form, sizec[32];
	char sign = ' ';

	form  = (char *) format;
	start = (unsigned long) *buffer;

	form++;
	if(*form == '0' || *form == '.') {
		sign = '0';
		form++;
	}

	while(*form != '\0') {
		switch(*form) {
			case 'u':
			case 'd':
			case 'i':
				sizec[i] = '\0';
				value = (unsigned long) var;
				signBit = 0x1ULL << (length_mod * 8 - 1);
				if (signBit & value) {
					**buffer = '-';
					*buffer += 1;
					value = (-(unsigned long)value) & convert[length_mod];
				}
				print_fill(buffer, sizec, value, 10, sign, 0);
				print_itoa(buffer, value, 10);
				break;
			case 'X':
			case 'x':
				sizec[i] = '\0';
				value = (unsigned long) var & convert[length_mod];
				print_fill(buffer, sizec, value, 16, sign, 0);
				print_itoa(buffer, value, 16);
				break;
			case 'O':
			case 'o':
				sizec[i] = '\0';
				value = (long int) var & convert[length_mod];
				print_fill(buffer, sizec, value, 8, sign, 0);
				print_itoa(buffer, value, 8);
				break;
			case 'p':
				sizec[i] = '\0';
				print_fill(buffer, sizec, (unsigned long) var, 16, ' ', 2);
				**buffer = '0';
				*buffer += 1;	
				**buffer = 'x';
				*buffer += 1;
				print_itoa(buffer,(unsigned long) var, 16);
				break;
			case 'c':
				sizec[i] = '\0';
				print_fill(buffer, sizec, 1, 10, ' ', 0);
				**buffer = (unsigned long) var;
				*buffer += 1;
				break;
			case 's':
				sizec[i] = '\0';
				sizei = strtoul(sizec, NULL, 10);
				len = strlen((char *) var);
				if(sizei > len) {
					for(i = 0; i < (sizei - len); i++) {
						**buffer = ' ';
						*buffer += 1;
					}
				}
				for(i = 0; i < strlen((char *) var); i++) {
					**buffer = ((char *) var)[i];
					*buffer += 1;
				}
				break;
			case 'l':
				form++;
				if(*form == 'l') {
					length_mod = sizeof(long long int);
				} else {
					form--;
					length_mod = sizeof(long int);
				}
				break;
			case 'h':
				form++;
				if(*form == 'h') {
					length_mod = sizeof(signed char);
				} else {
					form--;
					length_mod = sizeof(short int);
				}
				break;
			default:
				if(*form >= '0' && *form <= '9')
					sizec[i++] = *form;
		}
		form++;
	}

	
	return (long int) (*buffer - start);
}


/*
 * The vsnprintf function prints a formated strings into a buffer.
 * BUG: buffer size checking does not fully work yet
 */
int
vsnprintf(char *buffer, size_t bufsize, const char *format, va_list arg)
{
	char *ptr, *bstart;

	bstart = buffer;
	ptr = (char *) format;

	while(*ptr != '\0' && (buffer - bstart) < bufsize)
	{
		if(*ptr == '%') {
			char formstr[20];
			int i=0;
			
			do {
				formstr[i] = *ptr;
				ptr++;
				i++;
			} while(!(*ptr == 'd' || *ptr == 'i' || *ptr == 'u' || *ptr == 'x' || *ptr == 'X'
						|| *ptr == 'p' || *ptr == 'c' || *ptr == 's' || *ptr == '%'
						|| *ptr == 'O' || *ptr == 'o' )); 
			formstr[i++] = *ptr;
			formstr[i] = '\0';
			if(*ptr == '%') {
				*buffer++ = '%';
			} else {
				print_format(&buffer, formstr, va_arg(arg, void *));
			}
			ptr++;
		} else {

			*buffer = *ptr;

			buffer++;
			ptr++;
		}
	}
	
	*buffer = '\0';

	return (buffer - bstart);
}
