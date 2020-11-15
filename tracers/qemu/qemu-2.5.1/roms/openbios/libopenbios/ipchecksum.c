/* Taken from Etherboot */

#include "libopenbios/ipchecksum.h"

unsigned short ipchksum(const void *data, unsigned long length)
{
	unsigned long sum;
	unsigned long i;
	const unsigned char *ptr;
	union {
	    unsigned char byte[2];
	    unsigned short word;
	} u;

	/* In the most straight forward way possible,
	 * compute an ip style checksum.
	 */
	sum = 0;
	ptr = data;
	for(i = 0; i < length; i++) {
		unsigned long value;
		value = ptr[i];
		if (i & 1) {
			value <<= 8;
		}
		/* Add the new value */
		sum += value;
		/* Wrap around the carry */
		if (sum > 0xFFFF) {
			sum = (sum + (sum >> 16)) & 0xFFFF;
		}
	}
	u.byte[0] = (unsigned char) sum;
	u.byte[1] = (unsigned char) (sum >> 8);
	return (unsigned short) ~u.word;
}

unsigned short add_ipchksums(unsigned long offset, unsigned short sum, unsigned short new)
{
	unsigned long checksum;
	sum = ~sum & 0xFFFF;
	new = ~new & 0xFFFF;
	if (offset & 1) {
		/* byte swap the sum if it came from an odd offset
		 * since the computation is endian independant this
		 * works.
		 */
		new = (new << 8) | (new >> 8);
	}
	checksum = sum + new;
	if (checksum > 0xFFFF) {
		checksum -= 0xFFFF;
	}
	return (~checksum) & 0xFFFF;
}
