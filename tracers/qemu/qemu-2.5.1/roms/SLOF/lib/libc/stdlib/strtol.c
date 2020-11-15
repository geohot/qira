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

#include <stdlib.h>

long int strtol(const char *S, char **PTR,int BASE)
{
	long rval = 0;
	short int negative = 0;
	short int digit;
	// *PTR is S, unless PTR is NULL, in which case i override it with my own ptr
	char* ptr;
	if (PTR == 0)
	{
		//override
		PTR = &ptr;
	}
	// i use PTR to advance through the string
	*PTR = (char *) S;
	//check if BASE is ok
	if ((BASE < 0) || BASE > 36)
	{
		return 0;
	}
	// ignore white space at beginning of S
	while ((**PTR == ' ')
			|| (**PTR == '\t')
			|| (**PTR == '\n')
			|| (**PTR == '\r')
			)
	{
		(*PTR)++;
	}
	// check if S starts with "-" in which case the return value is negative
	if (**PTR == '-')
	{
		negative = 1;
		(*PTR)++;
	}
	// if BASE is 0... determine the base from the first chars...
	if (BASE == 0)
	{
		// if S starts with "0x", BASE = 16, else 10
		if ((**PTR == '0') && (*((*PTR)+1) == 'x'))
		{
			BASE = 16;
			(*PTR)++;
			(*PTR)++;
		}
		else
		{
			BASE = 10;
		}
	}
	if (BASE == 16)
	{
		// S may start with "0x"
		if ((**PTR == '0') && (*((*PTR)+1) == 'x'))
		{
			(*PTR)++;
			(*PTR)++;
		}
	}
	//until end of string
	while (**PTR)
	{
		if (((**PTR) >= '0') && ((**PTR) <= '9'))
		{
			//digit (0..9)
			digit = **PTR - '0';
		}
		else if (((**PTR) >= 'a') && ((**PTR) <='z'))
		{
			//alphanumeric digit lowercase(a (10) .. z (35) )
			digit = (**PTR - 'a') + 10;
		}
		else if (((**PTR) >= 'A') && ((**PTR) <='Z'))
		{
			//alphanumeric digit uppercase(a (10) .. z (35) )
			digit = (**PTR - 'A') + 10;
		}
		else
		{
			//end of parseable number reached...
			break;
		}
		if (digit < BASE)
		{
			rval = (rval * BASE) + digit;
		}
		else
		{
			//digit found, but its too big for current base
			//end of parseable number reached...
			break;
		}
		//next...
		(*PTR)++;
	}
	if (negative)
	{
		return rval * -1;
	}
	//else
	return rval;
}
