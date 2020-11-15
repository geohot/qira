
#define __bswap32(x) \
	((((x) & 0xff000000) >> 24) | (((x) & 0x00ff0000) >>  8) | \
	(((x) & 0x0000ff00) <<  8) | (((x) & 0x000000ff) << 24))

static int little_endian(void)
{
	static short one=1;
	return *(char *)&one==1;
}

static unsigned int ntohl(unsigned int netlong)
{
	if(little_endian())
		return __bswap32(netlong);

	return netlong;
}
