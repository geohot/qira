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
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

#include <cfgparse.h>

int verbose = 0;

#define dprintf(fmt, args...) if (verbose) printf(fmt, ##args)

static void
print_usage(void)
{
	printf
	    ("Usage: build_romfs [-?] [--help] [-s|--romfs-size <romfs_size>]\n"
	     "\t[-p|--smart-pad] [-n|--notime] <config-file> <output-file>\n");
}

unsigned long
str_to_num(const char *str)
{
	char *s = (char *) str;
	unsigned long num = strtoul(s, &s, 0);
	if (s) {
		if (s[0] == 'K')
			num <<= 10;
		if (s[0] == 'M')
			num <<= 20;
	}
	return num;
}

/*
 * NOTE: We should consider to install an exit handler which does the
 * unlink() of the output file. In case of error we just do exit() and
 * forget about all the clumsy error handling free/close code, which
 * blows up the code significantly and makes it hard to read.
 */
int
main(int argc, char *argv[])
{
	int conf_file, rc;
	struct ffs_chain_t ffs_chain;
	int c;
	int smart_pad = 0;	/* default */
	int notime = 0;
	const char *config_file = "boot_rom.ffs";
	const char *output_file = "boot_rom.bin";

	memset((void *) &ffs_chain, 0, sizeof(struct ffs_chain_t));

	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			{"romfs-size", 1, 0, 's'},
			{"smart-pad", 0, 0, 'p'},
			{"notime", 0, 0, 'n'},
			{"verbose", 0, 0, 'v'},
			{"help", 1, 0, 'h'},
			{0, 0, 0, 0}
		};
		c = getopt_long(argc, argv, "s:ph?nv", long_options,
				&option_index);
		if (c == -1)
			break;

		switch (c) {
		case 's':
			ffs_chain.romfs_size = str_to_num(optarg);
			break;
		case 'p':
			smart_pad = 1;
			break;
		case 'n':
			notime = 1;
			break;
		case 'v':
			verbose = 1;
			break;
		case '?':
		case 'h':
			print_usage();
			return EXIT_SUCCESS;
		default:
			printf("?? getopt returned character code 0%o ??\n", c);
		}
	}

	/* two files must always be specified: config-file and output-file */
	if (optind + 2 != argc) {
		print_usage();
		return EXIT_FAILURE;
	}

	config_file = argv[optind++];
	output_file = argv[optind++];

	dprintf("ROMFS FILESYSTEM CREATION V0.3 (bad parser)\n"
		"Build directory structure...\n"
		"  smart padding %s, maximum romfs size %d bytes\n",
		smart_pad ? "enabled" : "disabled", ffs_chain.romfs_size);

	conf_file = open(config_file, O_RDONLY);
	if (0 >= conf_file) {
		perror("load config file:");
		return EXIT_FAILURE;
	}

	rc = read_config(conf_file, &ffs_chain);
	close(conf_file);
	if (rc < 1) {
		fprintf(stderr, "flash cannot be built due to config errors\n");
		return EXIT_FAILURE;
	}

	rc = EXIT_SUCCESS;

	if (verbose)
		dump_fs_contents(&ffs_chain);
	if (smart_pad)
		/* FIXME: size is only verified during reorder */
		rc = reorder_ffs_chain(&ffs_chain);

	if (rc == EXIT_FAILURE)
		goto out;

	dprintf("Build ffs and write to image file...\n");
	if (build_ffs(&ffs_chain, output_file, notime) != 0) {
		fprintf(stderr, "build ffs failed\n");
		rc = EXIT_FAILURE;
	} else {
		rc = EXIT_SUCCESS;
	}

	/* Check if there are any duplicate entries in the image,
	   print warning if this is the case. */
	find_duplicates(&ffs_chain);
	free_chain_memory(&ffs_chain);
	dprintf("\n");

      out:
	/* If the build failed, remove the target image file */
	if (rc == EXIT_FAILURE)
		unlink(output_file);

	return rc;
}
