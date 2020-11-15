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

#ifndef GETOPT_H
#define GETOPT_H

extern char *optarg;
extern int optind;
extern int opterr;
extern int optopt;

struct option {
	const char *name;
	int has_arg;
	int *flag;
	int val;
};

enum {
	no_argument = 0,
	required_argument,
	optional_argument
};

int getopt(int argc, char **, const char *);
int getopt_long(int argc, char **, const char *, const struct option *, int *);

#endif				/* GETOPT_H */
