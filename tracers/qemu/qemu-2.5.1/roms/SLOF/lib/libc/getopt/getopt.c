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

/*
 * includes
 *******************************************************************************
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>

/*
 * global variables, types & constants
 * may be removed if already defined
 *******************************************************************************
 */
int opterr = 1;
int optopt = 0;
int optind = 1;
char *optarg = NULL;

/*
 * internal values needed by getopt
 * DO NOT CHANGE or REMOVE
 */
enum {
	OPTIONAL_ARG = 0,
	MANDATORY_ARG = 1,
	NO_ARG = 2
};

/*
 * variables needed by getopt & getopt_long!
 * DO NOT REMOVE
 */
static char *optstart = NULL;

int
getopt(int argc, char **argv, const char *options)
{
	char *optptr;
	char *argptr;
	int optman;
	int idx;
	int ret = 0;
	int argpresent;

	/*
	 * reset used global values
	 */
	optopt = 0;
	optarg = NULL;

	/*
	 * reset getopt if a new argv pointer is passed
	 */
	if (optstart != argv[0]) {
		optopt = 0;
		optind = 1;
		optarg = NULL;
		optstart = argv[0];
	}

	/*
	 * return if no more arguments are available
	 */
	if (optind >= argc) {
		return -1;
	}

	/*
	 * start parsing argv[optind]
	 */
	idx = 0;

	/*
	 * return if the option does not begin with a '-' or has more than 2 characters
	 */
	if (argv[optind][idx] != '-') {

		if (opterr != 0) {
			printf("unknown option \'%s\', expecting \'-\'\n",
			       argv[optind]);
		}

		optopt = (int) argv[optind][idx];
		optind++;

		return '?';
	}

	/*
	 * continue to the next character in argv[optind]
	 */
	idx++;

	/*
	 * identify the option
	 * make sure if an option contains a ':' to invalidate the option
	 */
	optptr = strchr(argv[optind], ':');

	if (optptr == NULL) {
		optptr = strchr(options, (int) argv[optind][idx]);
	} else {
		optptr = NULL;
	}

	/*
	 * check whether the option is present
	 */
	if (optptr == NULL) {
		/*
		 * unknown option detected
		 */
		if (opterr != 0) {
			printf("unknown option \'%s\'\n", argv[optind]);
		}

		optopt = (int) argv[optind][idx];
		optind++;

		return '?';
	}

	/*
	 * the option is present in the option string
	 * setup return value
	 */
	ret = (int) *optptr;

	/*
	 * get option argument if needed
	 */
	optptr++;

	/*
	 * determine between mandatory and optional argument
	 */
	optman = NO_ARG;

	if (*optptr == ':') {
		optman--;	// now set to MANDATORY_ARG
	}

	if (optman == MANDATORY_ARG) {
		optptr++;

		if (*optptr == ':') {
			optman--;	// now set to OPTIONAL_ARG
		}

	}

	/*
	 * if strlen( argv[optind ) is greater than 2,
	 * the argument is in the same argv
	 */
	if (strlen(argv[optind]) > 2) {
		argptr = &argv[optind][2];

		/*
		 * do not allow '-' in an argument
		 */
		if (strchr(argptr, '-') != NULL) {

			if (opterr != 0) {
				printf
				    ("illegal argument value \'%s\' for option \'-%c\'\n",
				     argptr, ret);
			}

			optopt = ret;

			return '?';
		}

	} else {
		/*
		 * move on to the next argv
		 * it now either contains an argument or the next option
		 */
		optind++;

		/*
		 * make sure not to overflow
		 */
		if (optind < argc) {
			argptr = argv[optind];
		} else {
			argptr = NULL;
		}

	}

	/*
	 * do the needed actions for the argument state
	 */
	switch (optman) {
	case OPTIONAL_ARG:

		if (argptr == NULL) {
			break;
		}

		if (*argptr != '-') {
			/*
			 * argument present
			 */
			optarg = argptr;
			optind++;

		}


		break;

	case MANDATORY_ARG:
		argpresent = (argptr != NULL);

		if (argpresent) {
			argpresent = (*argptr != '-');
		}

		if (argpresent) {
			/*
			 * argument present
			 */
			optarg = argptr;
			optind++;
		} else {
			/*
			 * mandatory argument missing
			 */
			if (opterr != 0) {
				printf
				    ("missing argument for option \'-%c\'\n",
				     ret);
			}

			optopt = ret;

			/*
			 * if the first character of options is a ':'
			 * return a ':' instead of a '?' in case of
			 * a missing argument
			 */
			if (*options == ':') {
				ret = ':';
			} else {
				ret = '?';
			}

		}


		break;

	case NO_ARG:

		if (strlen(argv[optind - 1]) > 2) {

			if (opterr != 0) {
				printf
				    ("too many arguments for option \'-%c\'\n",
				     ret);
			}

			optopt = ret;
			ret = '?';
		}


		break;

	}

	return ret;
}

int
getopt_long(int argc, char **argv, const char *shortopts,
	    const struct option *longopts, int *indexptr)
{
	struct option *optptr = (struct option *) longopts;
	int optidx = 0;
	int idx;
	int ret = 0;
	int argpresent;

	/*
	 * reset used global values
	 */
	optopt = 0;
	optarg = NULL;

	/*
	 * reset indexptr
	 */
	*indexptr = -1;

	/*
	 * reset getopt if a new argv pointer is passed
	 */
	if (optstart != argv[0]) {
		optopt = 0;
		optind = 1;
		optarg = NULL;
		optstart = argv[0];
	}

	/*
	 * return if no more arguments are available
	 */
	if (optind >= argc) {
		return -1;
	}

	/*
	 * start parsing argv[optind]
	 */
	idx = 0;

	/*
	 * return if the option does not begin with a '-'
	 */
	if (argv[optind][idx] != '-') {
		printf("unknown option \'%s\', expecting \'-\'\n",
		       argv[optind]);

		optind++;

		return '?';
	}

	/*
	 * move on to the next character in argv[optind]
	 */
	idx++;

	/*
	 * return getopt() in case of a short option
	 */
	if (argv[optind][idx] != '-') {
		return getopt(argc, argv, shortopts);
	}

	/*
	 * handle a long option
	 */
	idx++;

	while (optptr->name != NULL) {

		if (strcmp(&argv[optind][idx], optptr->name) == 0) {
			break;
		}

		optptr++;
		optidx++;
	}

	/*
	 * no matching option found
	 */
	if (optptr->name == NULL) {
		printf("unknown option \'%s\'\n", argv[optind]);

		optind++;

		return '?';
	}

	/*
	 * option was found, set up index pointer
	 */
	*indexptr = optidx;

	/*
	 * get argument
	 */
	optind++;

	switch (optptr->has_arg) {
	case no_argument:
		/*
		 * nothing to do
		 */

		break;

	case required_argument:
		argpresent = (optind != argc);

		if (argpresent) {
			argpresent = (argv[optind][0] != '-');
		}

		if (argpresent) {
			/*
			 * argument present
			 */
			optarg = argv[optind];
			optind++;
		} else {
			/*
			 * mandatory argument missing
			 */
			printf("missing argument for option \'%s\'\n",
			       argv[optind - 1]);

			ret = '?';
		}


		break;

	case optional_argument:

		if (optind == argc) {
			break;
		}

		if (argv[optind][0] != '-') {
			/*
			 * argument present
			 */
			optarg = argv[optind];
			optind++;
		}


		break;

	default:
		printf("unknown argument option for option \'%s\'\n",
		       argv[optind - 1]);

		ret = '?';

		break;

	}

	/*
	 * setup return values
	 */
	if (ret != '?') {

		if (optptr->flag == NULL) {
			ret = optptr->val;
		} else {
			*optptr->flag = optptr->val;
			ret = 0;
		}

	}

	return ret;
}
