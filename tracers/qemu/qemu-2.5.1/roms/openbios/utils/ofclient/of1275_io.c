#include "of1275.h"

static int of_write_initialized = 0;
static int stdout_ihandle = 0;
static int of_read_initialized = 0;
static int stdin_ihandle = 0;

int write(int fd, char *buf, int len)
{
	int actual;

	if (fd != 1 && fd != 2) {
		// printk("write: bad id %x\n", fd);
		exit(1);
	}

	if (!of_write_initialized) {
		stdout_ihandle =
		    of_find_integer_property("/chosen", "stdout");
		// printk("stdout_ihandle: %x\n",stdout_ihandle);
		of_write_initialized = 1;
	}

	of1275_write(stdout_ihandle, buf, len, &actual);
	return actual;
}

int read(int fd, char *buf, int len)
{
	int actual;

	if (fd != 0) {
		// printk("write: bad id %x\n", fd);
		exit(1);
	}

	if (!of_read_initialized) {
		stdin_ihandle =
		    of_find_integer_property("/chosen", "stdin");
		of_read_initialized = 1;
	}

	of1275_read(stdin_ihandle, buf, len, &actual);
	return actual;
}

exit(int status)
{
	of1275_exit(status);
	while (1);
}
