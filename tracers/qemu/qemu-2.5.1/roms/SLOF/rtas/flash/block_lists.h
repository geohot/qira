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

extern int progress;
extern unsigned char sig_org[];

int print_progress(void);
void print_hash(void);
int get_block_list_version(unsigned char *);
int image_check_crc(unsigned long *, int);
long get_size(unsigned long *, int);
void print_writing(void);
void write_block_list(unsigned long *, int);
int check_platform(unsigned long *, unsigned int, int);
