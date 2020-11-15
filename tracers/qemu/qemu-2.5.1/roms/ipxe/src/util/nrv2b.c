/**************************************************************
    Form adapted from lzhuf.c
    written by Haruyasu Yoshizaki 11/20/1988
    some minor changes 4/6/1989
    comments translated by Haruhiko Okumura 4/7/1989

    minor beautifications and adjustments for compiling under Linux
    by Markus Gutschke <gutschk@math.uni-muenster.de>
    						1997-01-27

    Modifications to allow use as a filter by Ken Yap
    <ken_yap@users.sourceforge.net>.

						1997-07-01

    Small mod to cope with running on big-endian machines
    by Jim Hague <jim.hague@acm.org)
						1998-02-06

    Make compression statistics report shorter
    by Ken Yap <ken_yap@users.sourceforge.net>.
						2001-04-25

    Replaced algorithm with nrv2b from ucl the compression
    library from upx.  That code is:
    Copyright (C) 1996-2002 Markus Franz Xaver Johannes Oberhumer
    And is distributed under the terms of the GPL.
    The conversion was performed 
    by Eric Biederman <ebiederman@lnxi.com>.
                                             20 August 2002
                                                
**************************************************************/
#define UCLPACK_COMPAT 0
#define NDEBUG 1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#ifdef __FreeBSD__
#include <inttypes.h>
#else
#include <stdint.h>
#endif
#include <limits.h>
#include <assert.h>
#if UCLPACK_COMPAT
#include <netinet/in.h>
#endif

#ifndef VERBOSE
#define Fprintf(x)
#define wterr     0
#else
#define Fprintf(x) fprintf x
#endif

#ifndef MAIN
extern
#endif
FILE  *infile, *outfile;

#if defined(ENCODE) || defined(DECODE)

#ifndef ENDIAN
#define ENDIAN   0
#endif
#ifndef BITSIZE
#define BITSIZE 32
#endif

static __inline__ void Error(char *message)
{
	Fprintf((stderr, "\n%s\n", message));
	exit(EXIT_FAILURE);
}

/* These will be a complete waste of time on a lo-endian */
/* system, but it only gets done once so WTF. */
static unsigned long __attribute__ (( unused )) i86ul_to_host(unsigned long ul)
{
	unsigned long res = 0;
	int i;
	union
	{
		unsigned char c[4];
		unsigned long ul;
	} u;

	u.ul = ul;
	for (i = 3; i >= 0; i--)
		res = (res << 8) + u.c[i];
	return res;
}

static unsigned long host_to_i86ul(unsigned long ul)
{
	int i;
	union
	{
		unsigned char c[4];
		unsigned long ul;
	} u;

	for (i = 0; i < 4; i++)
	{
		u.c[i] = ul & 0xff;
		ul >>= 8;
	}
	return u.ul;
}
#endif



#if UCLPACK_COMPAT
/* magic file header for compressed files */
static const unsigned char magic[8] =
{ 0x00, 0xe9, 0x55, 0x43, 0x4c, 0xff, 0x01, 0x1a };

#endif

#ifdef ENCODE
/********** NRV2B_99 compression **********/

/* Note by limiting the ring buffer I have limited the maximum
 * offset to 64K.  Since etherboot rarely gets that big it
 * is not a problem and it gives me a firm guarantee
 * that I will never get a 3 byte string match that is encodes
 * to more than 9/8 it's original size.
 * That guaranteee is important to for the inplace decompressor.
 * There are better ways to do this if a larger offset and buffer
 * would give better compression.
 */
#define N       (65536ul)           /* size of ring buffer */
#define THRESHOLD       1           /* lower limit for match length */
#define F            2048           /* upper limit for match length */
#define M2_MAX_OFFSET                 0xd00

/* note: to use default values pass -1, i.e. initialize
 * this struct by a memset(x,0xff,sizeof(x)) */
struct ucl_compress_config
{
	int bb_endian;
	int bb_size;
	unsigned int max_offset;
	unsigned int max_match;
	int s_level;
	int h_level;
	int p_level;
	int c_flags;
	unsigned int m_size;
};

struct ucl_compress
{
	int init;

	unsigned int look;          /* bytes in lookahead buffer */
	
	unsigned int m_len;
	unsigned int m_off;
	
	unsigned int last_m_len;
	unsigned int last_m_off;
	
	const unsigned char *bp;
	const unsigned char *ip;
	const unsigned char *in;
	const unsigned char *in_end;
	unsigned char *out;
	
	uint64_t bb_b;
	unsigned bb_k;
	unsigned bb_c_endian;
	unsigned bb_c_s;
	unsigned bb_c_s8;
	unsigned char *bb_p;
	unsigned char *bb_op;
	
	struct ucl_compress_config conf;
	unsigned int *result;

	unsigned int textsize;      /* text size counter */
	unsigned int codesize;      /* code size counter */
	unsigned int printcount; /* counter for reporting progress every 1K
				    bytes */

	
	/* some stats */
	unsigned long lit_bytes;
	unsigned long match_bytes;
	unsigned long rep_bytes;
	unsigned long lazy;
};



#define getbyte(c)  ((c).ip < (c).in_end ? *((c).ip)++ : (-1))

#define UCL_E_OK               0
#define UCL_E_INVALID_ARGUMENT 1
#define UCL_E_OUT_OF_MEMORY    2
#define UCL_E_ERROR            3

/***********************************************************************
//
************************************************************************/

#define SWD_HSIZE	16384
#define SWD_MAX_CHAIN	2048
#undef SWD_BEST_OFF

#define HEAD3(b,p) \
    (((0x9f5f*(((((uint32_t)b[p]<<5)^b[p+1])<<5)^b[p+2]))>>5) & (SWD_HSIZE-1))

#define HEAD2(b,p)      (b[p] ^ ((unsigned)b[p+1]<<8))
#define NIL2              UINT_MAX

struct ucl_swd
{
/* public - "built-in" */
	unsigned int n;
	unsigned int f;
	unsigned int threshold;
	
/* public - configuration */
	unsigned int max_chain;
	unsigned int nice_length;
	int use_best_off;
	unsigned int lazy_insert;
	
/* public - output */
	unsigned int m_len;
	unsigned int m_off;
	unsigned int look;
	int b_char;
#if defined(SWD_BEST_OFF)
	unsigned int best_off[ SWD_BEST_OFF ];
#endif
	
/* semi public */
	struct ucl_compress *c;
	unsigned int m_pos;
#if defined(SWD_BEST_OFF)
	unsigned int best_pos[ SWD_BEST_OFF ];
#endif
	
/* private */
	const uint8_t *dict;
	const uint8_t *dict_end;
	unsigned int dict_len;
	
/* private */
	unsigned int ip;                /* input pointer (lookahead) */
	unsigned int bp;                /* buffer pointer */
	unsigned int rp;                /* remove pointer */
	unsigned int b_size;
	
	unsigned char *b_wrap;
	
	unsigned int node_count;
	unsigned int first_rp;

	unsigned char b [ N + F + F ];
	unsigned int head3 [ SWD_HSIZE ];
	unsigned int succ3 [ N + F ];
	unsigned int best3 [ N + F ];
	unsigned int llen3 [ SWD_HSIZE ];
	unsigned int head2 [ 65536U ];
};

#define s_head3(s,key)        s->head3[key]


#if !defined( NDEBUG)
static void assert_match(const struct ucl_swd * swd, unsigned int m_len,
	unsigned int m_off )

{
	const struct ucl_compress *c = swd->c;
	unsigned int d_off;
	
	assert(m_len >= 2);
	if (m_off <= (unsigned int) (c->bp - c->in))
	{
		assert(c->bp - m_off + m_len < c->ip);
		assert(memcmp(c->bp, c->bp - m_off, m_len) == 0);
	}
	else
	{
		assert(swd->dict != NULL);
		d_off = m_off - (unsigned int) (c->bp - c->in);
		assert(d_off <= swd->dict_len);
		if (m_len > d_off)
		{
			assert(memcmp(c->bp, swd->dict_end - d_off, d_off) ==
				0);

			assert(c->in + m_len - d_off < c->ip);
			assert(memcmp(c->bp + d_off, c->in, m_len - d_off) ==
				0);

		}
		else
		{
			assert(memcmp(c->bp, swd->dict_end - d_off, m_len) ==
				0);

		}
	}
}
#else
#  define assert_match(a,b,c)   ((void)0)
#endif

/***********************************************************************
//
************************************************************************/


static
void swd_initdict(struct ucl_swd *s, const uint8_t *dict, unsigned int dict_len)

{
	s->dict = s->dict_end = NULL;
	s->dict_len = 0;

	if (!dict || dict_len <= 0)
		return;
	if (dict_len > s->n)
	{
		dict += dict_len - s->n;
		dict_len = s->n;
	}

	s->dict = dict;
	s->dict_len = dict_len;
	s->dict_end = dict + dict_len;
	memcpy(s->b,dict,dict_len);
	s->ip = dict_len;
}


static
void swd_insertdict(struct ucl_swd *s, unsigned int node, unsigned int len)
{
	unsigned int key;

	s->node_count = s->n - len;
	s->first_rp = node;

	while (len-- > 0)
	{
		key = HEAD3(s->b,node);
		s->succ3[node] = s_head3(s,key);
		s->head3[key] = (unsigned int)(node);
		s->best3[node] = (unsigned int)(s->f + 1);
		s->llen3[key]++;
		assert(s->llen3[key] <= s->n);

		key = HEAD2(s->b,node);
		s->head2[key] = (unsigned int)(node);

		node++;
	}
}

/***********************************************************************
//
************************************************************************/


static
int swd_init(struct ucl_swd *s, const uint8_t *dict, unsigned int dict_len)
{
	unsigned int i = 0;

	if (s->n == 0)
		s->n = N;
	if (s->f == 0)
		s->f = F;
	s->threshold = THRESHOLD;
	if (s->n > N || s->f > F)
		return UCL_E_INVALID_ARGUMENT;

	/* defaults */
	s->max_chain = SWD_MAX_CHAIN;
	s->nice_length = s->f;
	s->use_best_off = 0;
	s->lazy_insert = 0;

	s->b_size = s->n + s->f;
	if (s->b_size + s->f >= UINT_MAX)
		return UCL_E_ERROR;
	s->b_wrap = s->b + s->b_size;
	s->node_count = s->n;

	memset(s->llen3, 0, sizeof(s->llen3[0]) * SWD_HSIZE);
	for (i = 0; i < 65536U; i++)
		s->head2[i] = NIL2;

	s->ip = 0;
	swd_initdict(s,dict,dict_len);
	s->bp = s->ip;
	s->first_rp = s->ip;

	assert(s->ip + s->f <= s->b_size);

	s->look = (unsigned int) (s->c->in_end - s->c->ip);
	if (s->look > 0)
	{
		if (s->look > s->f)
			s->look = s->f;
		memcpy(&s->b[s->ip],s->c->ip,s->look);
		s->c->ip += s->look;
		s->ip += s->look;
	}
	if (s->ip == s->b_size)
		s->ip = 0;

	if (s->look >= 2 && s->dict_len > 0)
		swd_insertdict(s,0,s->dict_len);

	s->rp = s->first_rp;
	if (s->rp >= s->node_count)
		s->rp -= s->node_count;
	else
		s->rp += s->b_size - s->node_count;

	/* unused i */
	/* unused c */
	return UCL_E_OK;
}


static
void swd_exit(struct ucl_swd *s)
{
	/* unused s */
	( void ) s;
}

#define swd_pos2off(s,pos) \
	(s->bp > (pos) ? s->bp - (pos) : s->b_size - ((pos) - s->bp))

/***********************************************************************
//
************************************************************************/

static __inline__
void swd_getbyte(struct ucl_swd *s)
{
	int c;

	if ((c = getbyte(*(s->c))) < 0)
	{
		if (s->look > 0)
			--s->look;
	}
	else
	{
		s->b[s->ip] = (uint8_t)(c);
		if (s->ip < s->f)
			s->b_wrap[s->ip] = (uint8_t)(c);
	}
	if (++s->ip == s->b_size)
		s->ip = 0;
	if (++s->bp == s->b_size)
		s->bp = 0;
	if (++s->rp == s->b_size)
		s->rp = 0;
}
/***********************************************************************
// remove node from lists
************************************************************************/

static __inline__
void swd_remove_node(struct ucl_swd *s, unsigned int node)
{
	if (s->node_count == 0)
	{
		unsigned int key;
		
#ifdef UCL_DEBUG
		if (s->first_rp != UINT_MAX)
		{
			if (node != s->first_rp)
				printf("Remove %5d: %5d %5d %5d %5d %6d %6d\n",

					node, s->rp, s->ip, s->bp, s->first_rp,
					s->ip - node, s->ip - s->bp);
			assert(node == s->first_rp);
			s->first_rp = UINT_MAX;
		}
#endif
		
		key = HEAD3(s->b,node);
		assert(s->llen3[key] > 0);
		--s->llen3[key];
		
		key = HEAD2(s->b,node);
		assert(s->head2[key] != NIL2);
		if ((unsigned int) s->head2[key] == node)
			s->head2[key] = NIL2;
	}
	else
		--s->node_count;
}


/***********************************************************************
//
************************************************************************/


static
void swd_accept(struct ucl_swd *s, unsigned int n)
{
	assert(n <= s->look);

	if (n > 0) do
	{
		unsigned int key;

		swd_remove_node(s,s->rp);

		/* add bp into HEAD3 */
		key = HEAD3(s->b,s->bp);
		s->succ3[s->bp] = s_head3(s,key);
		s->head3[key] = (unsigned int)(s->bp);
		s->best3[s->bp] = (unsigned int)(s->f + 1);
		s->llen3[key]++;
		assert(s->llen3[key] <= s->n);

		/* add bp into HEAD2 */
		key = HEAD2(s->b,s->bp);
		s->head2[key] = (unsigned int)(s->bp);

		swd_getbyte(s);
	} while (--n > 0);
}

/***********************************************************************
//
************************************************************************/

static
void swd_search(struct ucl_swd *s, unsigned int node, unsigned int cnt)
{
	const unsigned char *p1;
	const unsigned char *p2;
	const unsigned char *px;

	unsigned int m_len = s->m_len;
	const unsigned char * b  = s->b;
	const unsigned char * bp = s->b + s->bp;
	const unsigned char * bx = s->b + s->bp + s->look;
	unsigned char scan_end1;
	
	assert(s->m_len > 0);
	
	scan_end1 = bp[m_len - 1];
	for ( ; cnt-- > 0; node = s->succ3[node])
	{
		p1 = bp;
		p2 = b + node;
		px = bx;
		
		assert(m_len < s->look);
		
		if (
			p2[m_len - 1] == scan_end1 &&
			p2[m_len] == p1[m_len] &&
			p2[0] == p1[0] &&
			p2[1] == p1[1])
		{
			unsigned int i;
			assert(memcmp(bp,&b[node],3) == 0);
			
			p1 += 2; p2 += 2;
			do {} while (++p1 < px && *p1 == *++p2);
			i = p1 - bp;
			
#ifdef UCL_DEBUG
			if (memcmp(bp,&b[node],i) != 0)
				printf("%5ld %5ld %02x%02x %02x%02x\n",
					(long)s->bp, (long) node,
					bp[0], bp[1], b[node], b[node+1]);
#endif
			assert(memcmp(bp,&b[node],i) == 0);
			
#if defined(SWD_BEST_OFF)
			if (i < SWD_BEST_OFF)
			{
				if (s->best_pos[i] == 0)
					s->best_pos[i] = node + 1;
			}
#endif
			if (i > m_len)
			{
				s->m_len = m_len = i;
				s->m_pos = node;
				if (m_len == s->look)
					return;
				if (m_len >= s->nice_length)
					return;
				if (m_len > (unsigned int) s->best3[node])
					return;
				scan_end1 = bp[m_len - 1];
			}
		}
	}
}

static int swd_search2(struct ucl_swd *s)
{
	unsigned int key;
	
	assert(s->look >= 2);
	assert(s->m_len > 0);
	
	key = s->head2[ HEAD2(s->b,s->bp) ];
	if (key == NIL2)
		return 0;
#ifdef UCL_DEBUG
	if (memcmp(&s->b[s->bp],&s->b[key],2) != 0)
		printf("%5ld %5ld %02x%02x %02x%02x\n", (long)s->bp, (long)key,
			s->b[s->bp], s->b[s->bp+1], s->b[key], s->b[key+1]);
#endif
	assert(memcmp(&s->b[s->bp],&s->b[key],2) == 0);
#if defined(SWD_BEST_OFF)
	if (s->best_pos[2] == 0)
		s->best_pos[2] = key + 1;
#endif
	
	if (s->m_len < 2)
	{
		s->m_len = 2;
		s->m_pos = key;
	}
	return 1;
}

/***********************************************************************
//
************************************************************************/

static
void swd_findbest(struct ucl_swd *s)
{
	unsigned int key;
	unsigned int cnt, node;
	unsigned int len;

	assert(s->m_len > 0);

	/* get current head, add bp into HEAD3 */
	key = HEAD3(s->b,s->bp);
	node = s->succ3[s->bp] = s_head3(s,key);
	cnt = s->llen3[key]++;
	assert(s->llen3[key] <= s->n + s->f);
	if (cnt > s->max_chain && s->max_chain > 0)
		cnt = s->max_chain;
	s->head3[key] = (unsigned int)(s->bp);

	s->b_char = s->b[s->bp];
	len = s->m_len;
	if (s->m_len >= s->look)
	{
		if (s->look == 0)
			s->b_char = -1;
		s->m_off = 0;
		s->best3[s->bp] = (unsigned int)(s->f + 1);
	}
	else
	{
		if (swd_search2(s))
			if (s->look >= 3)
				swd_search(s,node,cnt);
		if (s->m_len > len)
			s->m_off = swd_pos2off(s,s->m_pos);
		s->best3[s->bp] = (unsigned int)(s->m_len);

#if defined(SWD_BEST_OFF)
		if (s->use_best_off)
		{
			int i;
			for (i = 2; i < SWD_BEST_OFF; i++)
				if (s->best_pos[i] > 0)
					s->best_off[i] =
						swd_pos2off(s,s->best_pos[i]-1);

				else
					s->best_off[i] = 0;
		}
#endif
	}

	swd_remove_node(s,s->rp);

	/* add bp into HEAD2 */
	key = HEAD2(s->b,s->bp);
	s->head2[key] = (unsigned int)(s->bp);
}


/***********************************************************************
//
************************************************************************/

static int
init_match ( struct ucl_compress *c, struct ucl_swd *s,
	const uint8_t *dict, unsigned int dict_len,
	uint32_t flags )
{
	int r;
	
	assert(!c->init);
	c->init = 1;
	
	s->c = c;
	
	c->last_m_len = c->last_m_off = 0;
	
	c->textsize = c->codesize = c->printcount = 0;
	c->lit_bytes = c->match_bytes = c->rep_bytes = 0;
	c->lazy = 0;
	
	r = swd_init(s,dict,dict_len);
	if (r != UCL_E_OK)
	{
		swd_exit(s);
		return r;
	}
	
	s->use_best_off = (flags & 1) ? 1 : 0;
	return UCL_E_OK;
}

static int
find_match ( struct ucl_compress *c, struct ucl_swd *s,
	unsigned int this_len, unsigned int skip )
{
	assert(c->init);
	
	if (skip > 0)
	{
		assert(this_len >= skip);
		swd_accept(s, this_len - skip);
		c->textsize += this_len - skip + 1;
	}
	else
	{
		assert(this_len <= 1);
		c->textsize += this_len - skip;
	}
	
	s->m_len = THRESHOLD;
#ifdef SWD_BEST_OFF
	if (s->use_best_off)
		memset(s->best_pos,0,sizeof(s->best_pos));
#endif
	swd_findbest(s);
	c->m_len = s->m_len;
	c->m_off = s->m_off;
	
	swd_getbyte(s);
	
	if (s->b_char < 0)
	{
		c->look = 0;
		c->m_len = 0;
		swd_exit(s);
	}
	else
	{
		c->look = s->look + 1;
	}
	c->bp = c->ip - c->look;
	
#if 0
	/* brute force match search */
	if (c->m_len > THRESHOLD && c->m_len + 1 <= c->look)
	{
		const uint8_t *ip = c->bp;
		const uint8_t *m  = c->bp - c->m_off;
		const uint8_t *in = c->in;
		
		if (ip - in > N)
			in = ip - N;
		for (;;)
		{
			while (*in != *ip)
				in++;
			if (in == ip)
				break;
			if (in != m)
				if (memcmp(in,ip,c->m_len+1) == 0)
					printf("%p %p %p %5d\n",in,ip,m,c->m_len);

			in++;
		}
	}
#endif
	
	return UCL_E_OK;
}


static int bbConfig(struct ucl_compress *c, int endian, int bitsize)
{
	if (endian != -1)
	{
		if (endian != 0)
			return UCL_E_ERROR;
		c->bb_c_endian = endian;
	}
	if (bitsize != -1)
	{
		if (bitsize != 8 && bitsize != 16 && bitsize != 32 && bitsize != 64)
			return UCL_E_ERROR;
		c->bb_c_s = bitsize;
		c->bb_c_s8 = bitsize / 8;
	}
	c->bb_b = 0; c->bb_k = 0;
	c->bb_p = NULL;
	c->bb_op = NULL;
	return UCL_E_OK;
}

static void bbWriteBits(struct ucl_compress *c)
{
	uint8_t *p = c->bb_p;
	uint64_t b = c->bb_b;

	p[0] = (uint8_t)(b >>  0);
	if (c->bb_c_s >= 16)
	{
		p[1] = (uint8_t)(b >>  8);
		if (c->bb_c_s >= 32)
		{
			p[2] = (uint8_t)(b >> 16);
			p[3] = (uint8_t)(b >> 24);
			if (c->bb_c_s == 64)
			{
				p[4] = (uint8_t)(b >> 32);
				p[5] = (uint8_t)(b >> 40);
				p[6] = (uint8_t)(b >> 48);
				p[7] = (uint8_t)(b >> 56);
			}
		}
	}
}


static void bbPutBit(struct ucl_compress *c, unsigned bit)
{
	assert(bit == 0 || bit == 1);
	assert(c->bb_k <= c->bb_c_s);

	if (c->bb_k < c->bb_c_s)
	{
		if (c->bb_k == 0)
		{
			assert(c->bb_p == NULL);
			c->bb_p = c->bb_op;
			c->bb_op += c->bb_c_s8;
		}
		assert(c->bb_p != NULL);
		assert(c->bb_p + c->bb_c_s8 <= c->bb_op);

		c->bb_b = (c->bb_b << 1) + bit;
		c->bb_k++;
	}
	else
	{
		assert(c->bb_p != NULL);
		assert(c->bb_p + c->bb_c_s8 <= c->bb_op);

		bbWriteBits(c);
		c->bb_p = c->bb_op;
		c->bb_op += c->bb_c_s8;
		c->bb_b = bit;
		c->bb_k = 1;
	}
}


static void bbPutByte(struct ucl_compress *c, unsigned b)
{
	/**printf("putbyte %p %p %x  (%d)\n", op, bb_p, x, bb_k);*/
	assert(c->bb_p == NULL || c->bb_p + c->bb_c_s8 <= c->bb_op);
	*c->bb_op++ = (uint8_t)(b);
}

static void bbFlushBits(struct ucl_compress *c, unsigned filler_bit)
{
	if (c->bb_k > 0)
	{
		assert(c->bb_k <= c->bb_c_s);
		while (c->bb_k != c->bb_c_s)
			bbPutBit(c, filler_bit);
		bbWriteBits(c);
		c->bb_k = 0;
	}
	c->bb_p = NULL;
}



/***********************************************************************
//
************************************************************************/


static void code_prefix_ss11(struct ucl_compress *c, uint32_t i)
{
	if (i >= 2)
	{
		uint32_t t = 4;
		i += 2;
		do {
			t <<= 1;
		} while (i >= t);
		t >>= 1;
		do {
			t >>= 1;
			bbPutBit(c, (i & t) ? 1 : 0);
			bbPutBit(c, 0);
		} while (t > 2);
	}
	bbPutBit(c, (unsigned)i & 1);
	bbPutBit(c, 1);
}

static void
code_match(struct ucl_compress *c, unsigned int m_len, const unsigned int m_off)

{
	while (m_len > c->conf.max_match)
	{
		code_match(c, c->conf.max_match - 3, m_off);
		m_len -= c->conf.max_match - 3;
	}
	
	c->match_bytes += m_len;
	if (m_len > c->result[3])
		c->result[3] = m_len;
	if (m_off > c->result[1])
		c->result[1] = m_off;

	bbPutBit(c, 0);

	if (m_off == c->last_m_off)
	{
		bbPutBit(c, 0);
		bbPutBit(c, 1);
	}
	else
	{
		code_prefix_ss11(c, 1 + ((m_off - 1) >> 8));
		bbPutByte(c, (unsigned)m_off - 1);
	}
	m_len = m_len - 1 - (m_off > M2_MAX_OFFSET);
	if (m_len >= 4)
	{
		bbPutBit(c,0);
		bbPutBit(c,0);
		code_prefix_ss11(c, m_len - 4);
	}
	else
	{
		bbPutBit(c, m_len > 1);
		bbPutBit(c, (unsigned)m_len & 1);
	}

	c->last_m_off = m_off;
}

static void
code_run(struct ucl_compress *c, const uint8_t *ii, unsigned int lit)
{
	if (lit == 0)
		return;
	c->lit_bytes += lit;
	if (lit > c->result[5])
		c->result[5] = lit;
	do {
		bbPutBit(c, 1);
		bbPutByte(c, *ii++);
	} while (--lit > 0);
}

/***********************************************************************
//
************************************************************************/

static int
len_of_coded_match(struct ucl_compress *c, unsigned int m_len, unsigned int
	m_off)

{
	int b;
	if (m_len < 2 || (m_len == 2 && (m_off > M2_MAX_OFFSET))
		|| m_off > c->conf.max_offset)
		return -1;
	assert(m_off > 0);
	
	m_len = m_len - 2 - (m_off > M2_MAX_OFFSET);
	
	if (m_off == c->last_m_off)
		b = 1 + 2;
	else
	{
		b = 1 + 10;
		m_off = (m_off - 1) >> 8;
		while (m_off > 0)
		{
			b += 2;
			m_off >>= 1;
		}
	}

	b += 2;
	if (m_len < 3)
		return b;
	m_len -= 3;

	do {
		b += 2;
		m_len >>= 1;
	} while (m_len > 0);

	return b;
}

int ucl_nrv2b_99_compress(
	const uint8_t *in, unsigned long in_len,
	uint8_t *out, unsigned long *out_len,
	unsigned int *result)
{
	const uint8_t *ii;
	unsigned int lit;
	unsigned int m_len, m_off;
	struct ucl_compress c_buffer;
	struct ucl_compress * const c = &c_buffer;
	struct ucl_swd *swd;
	unsigned int result_buffer[16];
	int r;

/* max compression */
#define SC_TRY_LAZY    2
#define SC_GOOD_LENGTH F
#define SC_MAX_LAZY    F
#define SC_NICE_LENGTH F
#define SC_MAX_CHAIN   4096
#define SC_FLAGS       1
#define SC_MAX_OFFSET  N
	
	memset(c, 0, sizeof(*c));
	c->ip = c->in = in;
	c->in_end = in + in_len;
	c->out = out;
	c->result = result ? result : result_buffer;
	memset(c->result, 0, 16*sizeof(*c->result));
	c->result[0] = c->result[2] = c->result[4] = UINT_MAX;
	result = NULL;
	memset(&c->conf, 0xff, sizeof(c->conf));
	r = bbConfig(c, ENDIAN, BITSIZE);
	if (r == 0)
		r = bbConfig(c, c->conf.bb_endian, c->conf.bb_size);
	if (r != 0)
		return UCL_E_INVALID_ARGUMENT;
	c->bb_op = out;
	
	ii = c->ip;             /* point to start of literal run */
	lit = 0;
	

	swd = (struct ucl_swd *) malloc(sizeof(*swd));
	if (!swd)
		return UCL_E_OUT_OF_MEMORY;

	swd->f = F;
	swd->n = N;
	if (in_len >= 256 && in_len < swd->n)
		swd->n = in_len;
	if (swd->f < 8 || swd->n < 256)
		return UCL_E_INVALID_ARGUMENT;

	r = init_match(c,swd,NULL,0, SC_FLAGS);
	if (r != UCL_E_OK)
	{
		free(swd);
		return r;
	}
	if (SC_MAX_CHAIN > 0)
		swd->max_chain = SC_MAX_CHAIN;
	if (SC_NICE_LENGTH > 0)
		swd->nice_length = SC_NICE_LENGTH;
	if (c->conf.max_match < swd->nice_length)
		swd->nice_length = c->conf.max_match;
	
	c->last_m_off = 1;
	r = find_match(c,swd,0,0);
	if (r != UCL_E_OK)
		return r;
	while (c->look > 0)
	{
		unsigned int ahead;
		unsigned int max_ahead;
		int l1, l2;
		
		c->codesize = c->bb_op - out;
		
		m_len = c->m_len;
		m_off = c->m_off;
		
		assert(c->bp == c->ip - c->look);
		assert(c->bp >= in);
		if (lit == 0)
			ii = c->bp;
		assert(ii + lit == c->bp);
		assert(swd->b_char == *(c->bp));
		
		if (m_len < 2 || (m_len == 2 && (m_off > M2_MAX_OFFSET))
			|| m_off > c->conf.max_offset)
		{
			/* a literal */
			lit++;
			swd->max_chain = SC_MAX_CHAIN;
			r = find_match(c,swd,1,0);
			assert(r == 0);
			continue;
		}
		
		/* a match */
		assert_match(swd,m_len,m_off);
		
		/* shall we try a lazy match ? */
		ahead = 0;
		if (SC_TRY_LAZY <= 0 || m_len >= SC_MAX_LAZY || m_off ==
			c->last_m_off)

		{
			/* no */
			l1 = 0;
			max_ahead = 0;
		}
		else
		{
			/* yes, try a lazy match */
			l1 = len_of_coded_match(c,m_len,m_off);
			assert(l1 > 0);
			max_ahead = SC_TRY_LAZY;
			if ((m_len - 1) < max_ahead) {
				max_ahead = m_len -1;
			}
		}
		
		while (ahead < max_ahead && c->look > m_len)
		{
			if (m_len >= SC_GOOD_LENGTH)
				swd->max_chain = SC_MAX_CHAIN >> 2;
			else
				swd->max_chain = SC_MAX_CHAIN;
			r = find_match(c,swd,1,0);
			ahead++;
			
			assert(r == 0);
			assert(c->look > 0);
			assert(ii + lit + ahead == c->bp);
			
			if (c->m_len < 2)
				continue;
			l2 = len_of_coded_match(c,c->m_len,c->m_off);
			if (l2 < 0)
				continue;
			if (l1 + (int)(ahead + c->m_len - m_len) * 5 > l2 +
				(int)(ahead) * 9)
			{
				c->lazy++;
				assert_match(swd,c->m_len,c->m_off);
				lit += ahead;
				assert(ii + lit == c->bp);
				goto lazy_match_done;
			}
		}
		
		assert(ii + lit + ahead == c->bp);
		
		/* 1 - code run */
		code_run(c,ii,lit);
		lit = 0;
		
		/* 2 - code match */
		code_match(c,m_len,m_off);
		swd->max_chain = SC_MAX_CHAIN;
		r = find_match(c,swd,m_len,1+ahead);
		assert(r == 0);
		
	lazy_match_done: ;
	}
	
	/* store final run */
	code_run(c,ii,lit);
	
	/* EOF */
	bbPutBit(c, 0);
	code_prefix_ss11(c, 0x1000000U);
	bbPutByte(c, 0xff);

	bbFlushBits(c, 0);
	
	assert(c->textsize == in_len);
	c->codesize = c->bb_op - out;
	*out_len = c->bb_op - out;
	
#if 0
	printf("%7ld %7ld -> %7ld   %7ld %7ld   %ld  (max: %d %d %d)\n",
		(long) c->textsize, (long) in_len, (long) c->codesize,
		c->match_bytes, c->lit_bytes,  c->lazy,
		c->result[1], c->result[3], c->result[5]);
#endif
	assert(c->lit_bytes + c->match_bytes == in_len);
	
	swd_exit(swd);
	free(swd);

	return UCL_E_OK;
}


void Encode(void)  /* compression */
{
	uint8_t *in, *out;
	unsigned long in_len, out_len;
	uint32_t tw;
	int r;
	fseek(infile, 0, SEEK_END);
	in_len = ftell(infile);
#ifdef VERBOSE
	if ((signed long)in_len < 0)
		Fprintf((stderr, "Errno: %d", errno));
#endif
#if UCLPACK_COMPAT
	{
		uint8_t byte;
		if (fwrite(magic, sizeof(magic), 1, outfile) != 1)
			Error("Can't write.");
		tw = htonl(0); /* flags */
		if (fwrite(&tw, sizeof(tw), 1, outfile) != 1)
			Error("Can't write.");
		byte = 0x2b;		/* method */
		if (fwrite(&byte, sizeof(byte), 1, outfile) != 1)
			Error("Can't write.");
		byte = 10;		/* level */
		if (fwrite(&byte, sizeof(byte), 1, outfile) != 1)
			Error("Can't write.");
		tw = htonl(256*1024);		/* block_size */
		if (fwrite(&tw, sizeof(tw), 1, outfile) != 1)
			Error("Can't write.");
		tw = htonl(in_len);
		if (fwrite(&tw, sizeof(tw), 1, outfile) != 1)
			Error("Can't write.");	/* output size of text */
	}
#else
	tw = host_to_i86ul(in_len);
	if (fwrite(&tw, sizeof(tw), 1, outfile) != 1)
		Error("Can't write.");	/* output size of text */
#endif	
	if (in_len == 0)
		return;
	rewind(infile);

	in = malloc(in_len);
	out_len = in_len + (in_len/8) + 256;
	out = malloc(out_len);
	if (!in || !out) {
		Error("Can't malloc");
	}
	if (fread(in, in_len, 1, infile) != 1) {
		Error("Can't read");
	}
	r = ucl_nrv2b_99_compress(in, in_len, out, &out_len, 0 );
	if (r != UCL_E_OK)
		Error("Compression failure\n");
#if UCLPACK_COMPAT
	tw = htonl(out_len);
	if (fwrite(&tw, sizeof(tw), 1, outfile) != 1)
		Error("Can't write.");	/* file size of text */

#endif
	if (fwrite(out, out_len, 1, outfile) != 1) {
		Error("Write error\n");
	}
#if UCLPACK_COMPAT
	tw = htonl(0); /* EOF marker */
	if (fwrite(&tw, sizeof(tw), 1, outfile) != 1)
		Error("Can't write.");

#endif

#ifdef	LONG_REPORT
	Fprintf((stdout, "input size    %ld bytes\n", in_len));
	Fprintf((stdout, "output size   %ld bytes\n", out_len));
	Fprintf((stdout, "input/output  %.3f\n", (double)in_len / out_len));
#else
	Fprintf((stdout, "input/output = %ld/%ld = %.3f\n", in_len, out_len,
		(double)in_len / out_len));
#endif
	
}

#endif

#ifdef DECODE

#define GETBIT_8(bb, src, ilen) \
    (((bb = bb & 0x7f ? bb*2 : ((unsigned)src[ilen++]*2+1)) >> 8) & 1)

#define GETBIT_LE16(bb, src, ilen) \
    (bb*=2,bb&0xffff ? (bb>>16)&1 : (ilen+=2,((bb=(src[ilen-2]+src[ilen-1]*256u)*2+1)>>16)&1))

#define GETBIT_LE32(bb, src, ilen) \
    (bc > 0 ? ((bb>>--bc)&1) : (bc=31,\
    bb=*(const uint32_t *)((src)+ilen),ilen+=4,(bb>>31)&1))

#define GETBIT_LE64(bb, src, ilen) \
    (bc > 0 ? ((bb>>--bc)&1) : (bc=63, \
    bb=*(const uint64_t *)((src)+ilen),ilen+=8,(bb>>63)&1))

#if ENDIAN == 0 && BITSIZE == 8
#define GETBIT(bb, src, ilen) GETBIT_8(bb, src, ilen)
#endif
#if ENDIAN == 0 && BITSIZE == 16
#define GETBIT(bb, src, ilen) GETBIT_LE16(bb, src, ilen)
#endif
#if ENDIAN == 0 && BITSIZE == 32
#define GETBIT(bb, src, ilen) GETBIT_LE32(bb, src, ilen)
#endif
#if ENDIAN == 0 && BITSIZE == 64
#define GETBIT(bb, src, ilen) GETBIT_LE64(bb, src, ilen)
#endif
#ifndef GETBIT
#error "Bad Combination of ENDIAN and BITSIZE values specified"
#endif

#undef SAFE

#ifdef SAFE
#define FAIL(x,r)   if (x) { Error(r); }
#else
#define FAIL(x,r)
#endif

void Decode(void)  /* recover */
{
	uint32_t tw;
	uint8_t *src, *dst;
	unsigned long max_src_len, src_len, dst_len;
	unsigned long ilen = 0, olen = 0, last_m_off =  1;
#if BITSIZE <= 32
	uint32_t bb = 0;
#elif BITSIZE == 64
	uint64_t bb = 0;
#endif
	unsigned bc = 0;
#if UCLPACK_COMPAT
	if (fseek(infile, sizeof(magic) + sizeof(tw) + 1 + 1 + sizeof(tw),
		SEEK_SET) != 0)

		Error("Seek Error");
	if (fread(&tw, sizeof(tw), 1, infile) < 1)
		Error("Can't read"); /* read size of text */
	dst_len = ntohl(tw);
	if (fread(&tw, sizeof(tw), 1, infile) < 1)
		Error("Can't read"); /* read size of file */
	max_src_len = ntohl(tw);
#else
	if (fread(&tw, sizeof(tw), 1, infile) < 1)
		Error("Can't read"); /* read size of text */
	dst_len = i86ul_to_host(tw);
	max_src_len = dst_len + (dst_len/8) + 256;
#endif
	if (dst_len == 0)
		return;
	dst = malloc(dst_len);
	if (!dst)
		Error("Can't malloc");
	src = malloc(max_src_len);
	if (!src)
		Error("Can't malloc");
	src_len = fread(src, 1, max_src_len, infile);
	if (src_len <= 0) 
		Error("Can't read");

	for(;;) {
		unsigned int m_off, m_len;
		while(GETBIT(bb, src, ilen)) {
			FAIL(ilen >= src_len, "input overrun");
			FAIL(olen >= dst_len, "output  overrun");
			dst[olen++] = src[ilen++];
		}
		m_off = 1;
		do {
			m_off = m_off*2 + GETBIT(bb, src, ilen);
			FAIL(ilen >= src_len, "input overrun");
			FAIL(m_off > 0xffffffU +3, "lookbehind overrun");
		} while (!GETBIT(bb, src, ilen));
		if (m_off == 2)
		{
			m_off = last_m_off;
		}
		else
		{
			FAIL(ilen >= src_len, "input overrun");
			m_off = (m_off - 3)*256 + src[ilen++];
			if (m_off == 0xffffffffU)
				break;
			last_m_off = ++m_off;
		}
		m_len = GETBIT(bb, src, ilen);
		m_len = m_len*2 + GETBIT(bb, src, ilen);
		if (m_len == 0) 
		{
			m_len++;
			do {
				m_len = m_len*2 + GETBIT(bb, src, ilen);
				FAIL(ilen >= src_len, "input overrun");
				FAIL(m_len >= dst_len, "output overrun");
			} while(!GETBIT(bb, src, ilen));
			m_len += 2;
		}
		m_len += (m_off > 0xd00);
		FAIL(olen + m_len > dst_len, "output overrun");
		FAIL(m_off > olen, "lookbeind overrun");
		{
			const uint8_t *m_pos;
			m_pos = dst + olen - m_off;
			dst[olen++] = *m_pos++;
			do {
				dst[olen++] = *m_pos++;
			} while(--m_len > 0);
		}
	}
	FAIL(ilen < src_len, "input not consumed");
	FAIL(ilen > src_len, "input overrun");
	assert(ilen == src_len);
	Fprintf((stderr, "%12ld\n", olen));
	if (dst_len != olen) {
		fprintf(stderr, "length != expected length\n");
	}
	if (fwrite(dst, olen, 1, outfile) != 1)
		Error("Write error\n");
	free(src);
	free(dst);
}
#endif

#ifdef MAIN
int main(int argc, char *argv[])
{
	char  *s;
	FILE  *f;
	int    c;
	
	if (argc == 2) {
		outfile = stdout;
		if ((f = tmpfile()) == NULL) {
			perror("tmpfile");
			return EXIT_FAILURE;
		}
		while ((c = getchar()) != EOF)
			fputc(c, f);
		rewind(infile = f);
	}
	else if (argc != 4) {
		Fprintf((stderr, "'nrv2b e file1 file2' encodes file1 into file2.\n"
			"'nrv2b d file2 file1' decodes file2 into file1.\n"));
		return EXIT_FAILURE;
	}
	if (argc == 4) {
		if ((s = argv[1], s[1] || strpbrk(s, "DEde") == NULL)
			|| (s = argv[2], (infile  = fopen(s, "rb")) == NULL)
			|| (s = argv[3], (outfile = fopen(s, "wb")) == NULL)) {
			Fprintf((stderr, "??? %s\n", s));
			return EXIT_FAILURE;
		}
	}
	if (toupper(*argv[1]) == 'E')
		Encode();
	else
		Decode();
	fclose(infile);
	fclose(outfile);
	return EXIT_SUCCESS;
}
#endif
