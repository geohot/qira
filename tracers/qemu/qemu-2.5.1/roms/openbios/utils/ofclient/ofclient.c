#include "of1275.h"

int write(int fd, char *buf, int len);

int main(void)
{
	write(1, "Hello world!\n", 13 );
	return 0;
}
