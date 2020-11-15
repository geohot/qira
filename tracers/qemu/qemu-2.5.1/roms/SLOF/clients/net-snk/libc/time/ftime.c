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


#include <time.h>
#include <rtas.h>
#include <stdio.h>

time_t
time(time_t *tod)
{
	dtime ts;

	rtas_get_time_of_day(&ts);
	printf("debug!!\n");
	
	printf("year  : %d\n", ts.year);
	printf("month : %d\n", ts.month);
	printf("day   : %d\n", ts.day);
	printf("hour  : %d\n", ts.hour);
	printf("minute: %d\n", ts.minute);
	printf("second: %d\n", ts.second);
	printf("nano  : %d\n", ts.nano);
	printf("debug ende\n");

//	if(tod)
//		*tod = t;
	return 0;
}
