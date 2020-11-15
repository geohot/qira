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
#include <string.h>

extern int main (int, char**);
extern int callback (int, char **);

int _start(char *arg_string, long len);
unsigned long callback_entry(void *base, unsigned long len);


#define MAX_ARGV 10
static int
gen_argv(const char *arg_string, int len, char* argv[])
{
  const char *str, *str_end, *arg_string_end = arg_string + len;
  int i;

  str = arg_string;
  for (i = 0; i < MAX_ARGV; i++)
    {
      str_end = str;

      while((*str_end++ != ' ') && (str_end <= arg_string_end));

      argv[i] = malloc(str_end-str);

      memcpy (argv[i], str, str_end-str-1);
      argv[i][str_end-str-1] = '\0';
      str = str_end-1;
      while(*(++str) == ' ');
      if (str >= arg_string_end)
	break;
    }
  return i+1;
}



int
_start(char * arg_string, long len)
{
    int rc;
    int argc;
    char* argv[MAX_ARGV];

    argc = gen_argv(arg_string, len, argv);

    rc = main(argc, argv);

    return rc;
}

/*
 * Takes a Forth representation of a string and generates an argument array,
 * then calls callback().
 */
unsigned long
callback_entry(void *base, unsigned long len) {
	char *argv[MAX_ARGV];
	int argc;

	argc = gen_argv(base, len, argv);

	return (callback(argc, argv));
}

