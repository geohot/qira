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


#ifndef _TIME_H_
#define _TIME_H_

typedef unsigned long clock_t;
typedef unsigned long time_t;

time_t time(time_t *);

extern unsigned long tb_freq;

/* setup the timer to start counting from the given parameter */
void set_timer(int);
/* read the current value from the decrementer */
int get_timer(void);
/* get the number of ticks for which the decrementer needs 1 second */
int get_sec_ticks(void);
/* get the number of ticks for which the decrementer needs 1 millisecond */
int get_msec_ticks(void);

#define TICKS_MSEC get_msec_ticks()
#define TICKS_SEC get_sec_ticks()

#endif
