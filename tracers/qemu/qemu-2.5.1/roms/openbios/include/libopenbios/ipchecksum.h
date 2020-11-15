#ifndef IPCHECKSUM_H
#define IPCHECKSUM_H

unsigned short ipchksum(const void *data, unsigned long length);
unsigned short add_ipchksums(unsigned long offset, unsigned short sum, unsigned short new);

#endif /* IPCHECKSUM_H */
