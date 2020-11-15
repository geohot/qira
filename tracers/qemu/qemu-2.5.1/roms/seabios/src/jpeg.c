/*
 * Copyright (C) 2001, Novell Inc.
 * Copyright (C) 2010  Kevin O'Connor <kevin@koconnor.net>
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions 
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of Novell nor the names of the contributors may 
 *    be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR "AS IS" AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, 
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 * 
 */

/*
 * a tiny jpeg decoder.
 *
 * written in August 2001 by Michael Schroeder <mls@suse.de>
 *
 */

#define __LITTLE_ENDIAN
#include "malloc.h"
#include "string.h"
#include "util.h"
#define ISHIFT 11

#define IFIX(a) ((int)((a) * (1 << ISHIFT) + .5))
#define IMULT(a, b) (((a) * (b)) >> ISHIFT)
#define ITOINT(a) ((a) >> ISHIFT)

#ifndef __P
# define __P(x) x
#endif

/* special markers */
#define M_BADHUFF        -1
#define M_EOF                0x80

struct in {
    unsigned char *p;
    unsigned int bits;
    int left;
    int marker;

    int (*func) __P((void *));
    void *data;
};

/*********************************/
struct dec_hufftbl;
struct enc_hufftbl;

union hufftblp {
    struct dec_hufftbl *dhuff;
    struct enc_hufftbl *ehuff;
};

struct scan {
    int dc;               /* old dc value */

    union hufftblp hudc;
    union hufftblp huac;
    int next;             /* when to switch to next scan */

    int cid;              /* component id */
    int hv;               /* horiz/vert, copied from comp */
    int tq;               /* quant tbl, copied from comp */
};

/*********************************/

#define DECBITS 10        /* seems to be the optimum */

struct dec_hufftbl {
    int maxcode[17];
    int valptr[16];
    unsigned char vals[256];
    unsigned int llvals[1 << DECBITS];
};

static void decode_mcus __P((struct in *, int *, int, struct scan *, int *));
static int dec_readmarker __P((struct in *));
static void dec_makehuff __P((struct dec_hufftbl *, int *, unsigned char *));

static void setinput __P((struct in *, unsigned char *));
/*********************************/

#undef PREC
#define PREC int

static void idctqtab __P((unsigned char *, PREC *));
static void idct __P((int *, int *, PREC *, PREC, int));
static void scaleidctqtab __P((PREC *, PREC));

/*********************************/

static void initcol __P((PREC[][64]));

static void col221111 __P((int *, unsigned char *, int));
static void col221111_16 __P((int *, unsigned char *, int));
static void col221111_32 __P((int *, unsigned char *, int));

/*********************************/

#define ERR_NO_SOI 1
#define ERR_NOT_8BIT 2
#define ERR_HEIGHT_MISMATCH 3
#define ERR_WIDTH_MISMATCH 4
#define ERR_BAD_WIDTH_OR_HEIGHT 5
#define ERR_TOO_MANY_COMPPS 6
#define ERR_ILLEGAL_HV 7
#define ERR_QUANT_TABLE_SELECTOR 8
#define ERR_NOT_YCBCR_221111 9
#define ERR_UNKNOWN_CID_IN_SCAN 10
#define ERR_NOT_SEQUENTIAL_DCT 11
#define ERR_WRONG_MARKER 12
#define ERR_NO_EOI 13
#define ERR_BAD_TABLES 14
#define ERR_DEPTH_MISMATCH 15

/*********************************/

#define M_SOI   0xd8
#define M_APP0  0xe0
#define M_DQT   0xdb
#define M_SOF0  0xc0
#define M_DHT   0xc4
#define M_DRI   0xdd
#define M_SOS   0xda
#define M_RST0  0xd0
#define M_EOI   0xd9
#define M_COM   0xfe

struct comp {
    int cid;
    int hv;
    int tq;
};

#define MAXCOMP 4
struct jpginfo {
    int nc;   /* number of components */
    int ns;   /* number of scans */
    int dri;  /* restart interval */
    int nm;   /* mcus til next marker */
    int rm;   /* next restart marker */
};

struct jpeg_decdata {
    int dcts[6 * 64 + 16];
    int out[64 * 6];
    int dquant[3][64];

    unsigned char *datap;
    struct jpginfo info;
    struct comp comps[MAXCOMP];
    struct scan dscans[MAXCOMP];
    unsigned char quant[4][64];
    struct dec_hufftbl dhuff[4];
    struct in in;

    int height, width;
};

static int getbyte(struct jpeg_decdata *jpeg)
{
    return *jpeg->datap++;
}

static int getword(struct jpeg_decdata *jpeg)
{
    int c1, c2;
    c1 = *jpeg->datap++;
    c2 = *jpeg->datap++;
    return c1 << 8 | c2;
}

static int readtables(struct jpeg_decdata *jpeg, int till)
{
    int m, l, i, j, lq, pq, tq;
    int tc, th, tt;

    for (;;) {
        if (getbyte(jpeg) != 0xff)
            return -1;
        if ((m = getbyte(jpeg)) == till)
            break;

        switch (m) {
        case 0xc2:
            return 0;

        case M_DQT:
            lq = getword(jpeg);
            while (lq > 2) {
                pq = getbyte(jpeg);
                tq = pq & 15;
                if (tq > 3)
                    return -1;
                pq >>= 4;
                if (pq != 0)
                    return -1;
                for (i = 0; i < 64; i++)
                    jpeg->quant[tq][i] = getbyte(jpeg);
                lq -= 64 + 1;
            }
            break;

        case M_DHT:
            l = getword(jpeg);
            while (l > 2) {
                int hufflen[16], k;
                unsigned char huffvals[256];

                tc = getbyte(jpeg);
                th = tc & 15;
                tc >>= 4;
                tt = tc * 2 + th;
                if (tc > 1 || th > 1)
                    return -1;
                for (i = 0; i < 16; i++)
                    hufflen[i] = getbyte(jpeg);
                l -= 1 + 16;
                k = 0;
                for (i = 0; i < 16; i++) {
                    for (j = 0; j < hufflen[i]; j++)
                        huffvals[k++] = getbyte(jpeg);
                    l -= hufflen[i];
                }
                dec_makehuff(jpeg->dhuff + tt, hufflen, huffvals);
            }
            break;

        case M_DRI:
            l = getword(jpeg);
            jpeg->info.dri = getword(jpeg);
            break;

        default:
            l = getword(jpeg);
            while (l-- > 2)
                getbyte(jpeg);
            break;
        }
    }
    return 0;
}

static void dec_initscans(struct jpeg_decdata *jpeg)
{
    int i;

    jpeg->info.nm = jpeg->info.dri + 1;
    jpeg->info.rm = M_RST0;
    for (i = 0; i < jpeg->info.ns; i++)
        jpeg->dscans[i].dc = 0;
}

static int dec_checkmarker(struct jpeg_decdata *jpeg)
{
    int i;

    if (dec_readmarker(&jpeg->in) != jpeg->info.rm)
        return -1;
    jpeg->info.nm = jpeg->info.dri;
    jpeg->info.rm = (jpeg->info.rm + 1) & ~0x08;
    for (i = 0; i < jpeg->info.ns; i++)
        jpeg->dscans[i].dc = 0;
    return 0;
}

struct jpeg_decdata *jpeg_alloc(void)
{
    struct jpeg_decdata *jpeg = malloc_tmphigh(sizeof(*jpeg));
    return jpeg;
}

int jpeg_decode(struct jpeg_decdata *jpeg, unsigned char *buf)
{
    int i, j, m, tac, tdc;

    if (!jpeg || !buf)
        return -1;
    jpeg->datap = buf;
    if (getbyte(jpeg) != 0xff)
        return ERR_NO_SOI;
    if (getbyte(jpeg) != M_SOI)
        return ERR_NO_SOI;
    if (readtables(jpeg, M_SOF0))
        return ERR_BAD_TABLES;
    getword(jpeg);
    i = getbyte(jpeg);
    if (i != 8)
        return ERR_NOT_8BIT;
    jpeg->height = getword(jpeg);
    jpeg->width = getword(jpeg);
    if ((jpeg->height & 15) || (jpeg->width & 15))
        return ERR_BAD_WIDTH_OR_HEIGHT;
    jpeg->info.nc = getbyte(jpeg);
    if (jpeg->info.nc > MAXCOMP)
        return ERR_TOO_MANY_COMPPS;
    for (i = 0; i < jpeg->info.nc; i++) {
        int h, v;
        jpeg->comps[i].cid = getbyte(jpeg);
        jpeg->comps[i].hv = getbyte(jpeg);
        v = jpeg->comps[i].hv & 15;
        h = jpeg->comps[i].hv >> 4;
        jpeg->comps[i].tq = getbyte(jpeg);
        if (h > 3 || v > 3)
            return ERR_ILLEGAL_HV;
        if (jpeg->comps[i].tq > 3)
            return ERR_QUANT_TABLE_SELECTOR;
    }
    if (readtables(jpeg, M_SOS))
        return ERR_BAD_TABLES;
    getword(jpeg);
    jpeg->info.ns = getbyte(jpeg);
    if (jpeg->info.ns != 3)
        return ERR_NOT_YCBCR_221111;
    for (i = 0; i < 3; i++) {
        jpeg->dscans[i].cid = getbyte(jpeg);
        tdc = getbyte(jpeg);
        tac = tdc & 15;
        tdc >>= 4;
        if (tdc > 1 || tac > 1)
            return ERR_QUANT_TABLE_SELECTOR;
        for (j = 0; j < jpeg->info.nc; j++)
            if (jpeg->comps[j].cid == jpeg->dscans[i].cid)
                break;
        if (j == jpeg->info.nc)
            return ERR_UNKNOWN_CID_IN_SCAN;
        jpeg->dscans[i].hv = jpeg->comps[j].hv;
        jpeg->dscans[i].tq = jpeg->comps[j].tq;
        jpeg->dscans[i].hudc.dhuff = &jpeg->dhuff[tdc];
        jpeg->dscans[i].huac.dhuff = &jpeg->dhuff[2 + tac];
    }

    i = getbyte(jpeg);
    j = getbyte(jpeg);
    m = getbyte(jpeg);

    if (i != 0 || j != 63 || m != 0)
        return ERR_NOT_SEQUENTIAL_DCT;

    if (jpeg->dscans[0].cid != 1 || jpeg->dscans[1].cid != 2
        || jpeg->dscans[2].cid != 3)
        return ERR_NOT_YCBCR_221111;

    if (jpeg->dscans[0].hv != 0x22 || jpeg->dscans[1].hv != 0x11
        || jpeg->dscans[2].hv != 0x11)
        return ERR_NOT_YCBCR_221111;

    idctqtab(jpeg->quant[jpeg->dscans[0].tq], jpeg->dquant[0]);
    idctqtab(jpeg->quant[jpeg->dscans[1].tq], jpeg->dquant[1]);
    idctqtab(jpeg->quant[jpeg->dscans[2].tq], jpeg->dquant[2]);
    initcol(jpeg->dquant);
    setinput(&jpeg->in, jpeg->datap);

#if 0
    /* landing zone */
    img[len] = 0;
    img[len + 1] = 0xff;
    img[len + 2] = M_EOF;
#endif

    dec_initscans(jpeg);

    return 0;
}

void jpeg_get_size(struct jpeg_decdata *jpeg, int *width, int *height)
{
    *width = jpeg->width;
    *height = jpeg->height;
}

int jpeg_show(struct jpeg_decdata *jpeg, unsigned char *pic, int width
              , int height, int depth, int bytes_per_line_dest)
{
    int m, mcusx, mcusy, mx, my, mloffset, jpgbpl;
    int max[6];

    if (jpeg->height != height)
        return ERR_HEIGHT_MISMATCH;
    if (jpeg->width != width)
        return ERR_WIDTH_MISMATCH;

    jpgbpl = width * depth / 8;
    mloffset = bytes_per_line_dest > jpgbpl ? bytes_per_line_dest : jpgbpl;

    mcusx = jpeg->width >> 4;
    mcusy = jpeg->height >> 4;

    jpeg->dscans[0].next = 6 - 4;
    jpeg->dscans[1].next = 6 - 4 - 1;
    jpeg->dscans[2].next = 6 - 4 - 1 - 1;        /* 411 encoding */
    for (my = 0; my < mcusy; my++) {
        for (mx = 0; mx < mcusx; mx++) {
            if (jpeg->info.dri && !--jpeg->info.nm)
                if (dec_checkmarker(jpeg))
                    return ERR_WRONG_MARKER;

            decode_mcus(&jpeg->in, jpeg->dcts, 6, jpeg->dscans, max);
            idct(jpeg->dcts, jpeg->out, jpeg->dquant[0],
                 IFIX(128.5), max[0]);
            idct(jpeg->dcts + 64, jpeg->out + 64, jpeg->dquant[0],
                 IFIX(128.5), max[1]);
            idct(jpeg->dcts + 128, jpeg->out + 128, jpeg->dquant[0],
                 IFIX(128.5), max[2]);
            idct(jpeg->dcts + 192, jpeg->out + 192, jpeg->dquant[0],
                 IFIX(128.5), max[3]);
            idct(jpeg->dcts + 256, jpeg->out + 256, jpeg->dquant[1],
                 IFIX(0.5), max[4]);
            idct(jpeg->dcts + 320, jpeg->out + 320, jpeg->dquant[2],
                 IFIX(0.5), max[5]);

            switch (depth) {
            case 32:
                col221111_32(jpeg->out,
                             pic + (my * 16 * mloffset + mx * 16 * 4),
                             mloffset);
                break;
            case 24:
                col221111(jpeg->out,
                          pic + (my * 16 * mloffset + mx * 16 * 3),
                          mloffset);
                break;
            case 16:
                col221111_16(jpeg->out,
                             pic + (my * 16 * mloffset + mx * 16 * 2),
                             mloffset);
                break;
            default:
                return ERR_DEPTH_MISMATCH;
                break;
            }
        }
    }

    m = dec_readmarker(&jpeg->in);
    if (m != M_EOI)
        return ERR_NO_EOI;

    return 0;
}

/****************************************************************/
/**************       huffman decoder             ***************/
/****************************************************************/

static int fillbits __P((struct in *, int, unsigned int));
static int dec_rec2 __P((struct in *, struct dec_hufftbl *, int *, int, int));

static void setinput(struct in *in, unsigned char *p)
{
    in->p = p;
    in->left = 0;
    in->bits = 0;
    in->marker = 0;
}

static int fillbits(struct in *in, int le, unsigned int bi)
{
    int b, m;

    if (in->marker) {
        if (le <= 16)
            in->bits = bi << 16, le += 16;
        return le;
    }
    while (le <= 24) {
        b = *in->p++;
        if (b == 0xff && (m = *in->p++) != 0) {
            if (m == M_EOF) {
                if (in->func && (m = in->func(in->data)) == 0)
                    continue;
            }
            in->marker = m;
            if (le <= 16)
                bi = bi << 16, le += 16;
            break;
        }
        bi = bi << 8 | b;
        le += 8;
    }
    in->bits = bi;                /* tmp... 2 return values needed */
    return le;
}

static int dec_readmarker(struct in *in)
{
    int m;

    in->left = fillbits(in, in->left, in->bits);
    if ((m = in->marker) == 0)
        return 0;
    in->left = 0;
    in->marker = 0;
    return m;
}

#define LEBI_DCL       int le, bi
#define LEBI_GET(in)   (le = in->left, bi = in->bits)
#define LEBI_PUT(in)   (in->left = le, in->bits = bi)

#define GETBITS(in, n) (                                     \
  (le < (n) ? le = fillbits(in, le, bi), bi = in->bits : 0), \
  (le -= (n)),                                               \
  bi >> le & ((1 << (n)) - 1)                                \
)

#define UNGETBITS(in, n) ( \
  le += (n)                \
)


static int dec_rec2(struct in *in, struct dec_hufftbl *hu, int *runp,
                    int c, int i)
{
    LEBI_DCL;

    LEBI_GET(in);
    if (i) {
        UNGETBITS(in, i & 127);
        *runp = i >> 8 & 15;
        i >>= 16;
    } else {
        for (i = DECBITS;
             (c = ((c << 1) | GETBITS(in, 1))) >= (hu->maxcode[i]); i++);
        if (i >= 16) {
            in->marker = M_BADHUFF;
            return 0;
        }
        i = hu->vals[hu->valptr[i] + c - hu->maxcode[i - 1] * 2];
        *runp = i >> 4;
        i &= 15;
    }
    if (i == 0) {                /* sigh, 0xf0 is 11 bit */
        LEBI_PUT(in);
        return 0;
    }
    /* receive part */
    c = GETBITS(in, i);
    if (c < (1 << (i - 1)))
        c += (-1 << i) + 1;
    LEBI_PUT(in);
    return c;
}

#define DEC_REC(in, hu, r, i)         (  \
  r = GETBITS(in, DECBITS),              \
  i = hu->llvals[r],                     \
  i & 128 ?                              \
    (                                    \
      UNGETBITS(in, i & 127),            \
      r = i >> 8 & 15,                   \
      i >> 16                            \
    )                                    \
  :                                      \
    (                                    \
      LEBI_PUT(in),                      \
      i = dec_rec2(in, hu, &r, r, i),    \
      LEBI_GET(in),                      \
      i                                  \
    )                                    \
)

static void decode_mcus(struct in *in, int *dct, int n, struct scan *sc,
                        int *maxp)
{
    struct dec_hufftbl *hu;
    int i, r, t;
    LEBI_DCL;

    memset(dct, 0, n * 64 * sizeof(*dct));
    LEBI_GET(in);
    while (n-- > 0) {
        hu = sc->hudc.dhuff;
        *dct++ = (sc->dc += DEC_REC(in, hu, r, t));

        hu = sc->huac.dhuff;
        i = 63;
        while (i > 0) {
            t = DEC_REC(in, hu, r, t);
            if (t == 0 && r == 0) {
                dct += i;
                break;
            }
            dct += r;
            *dct++ = t;
            i -= r + 1;
        }
        *maxp++ = 64 - i;
        if (n == sc->next)
            sc++;
    }
    LEBI_PUT(in);
}

static void dec_makehuff(struct dec_hufftbl *hu, int *hufflen,
                         unsigned char *huffvals)
{
    int code, k, i, j, d, x, c, v;
    for (i = 0; i < (1 << DECBITS); i++)
        hu->llvals[i] = 0;

    /*
     * llvals layout:
     *
     * value v already known, run r, backup u bits:
     *  vvvvvvvvvvvvvvvv 0000 rrrr 1 uuuuuuu
     * value unknown, size b bits, run r, backup u bits:
     *  000000000000bbbb 0000 rrrr 0 uuuuuuu
     * value and size unknown:
     *  0000000000000000 0000 0000 0 0000000
     */

    code = 0;
    k = 0;
    for (i = 0; i < 16; i++, code <<= 1) {        /* sizes */
        hu->valptr[i] = k;
        for (j = 0; j < hufflen[i]; j++) {
            hu->vals[k] = *huffvals++;
            if (i < DECBITS) {
                c = code << (DECBITS - 1 - i);
                v = hu->vals[k] & 0x0f;        /* size */
                for (d = 1 << (DECBITS - 1 - i); --d >= 0;) {
                    if (v + i < DECBITS) {        /* both fit in table */
                        x = d >> (DECBITS - 1 - v - i);
                        if (v && x < (1 << (v - 1)))
                            x += (-1 << v) + 1;
                        x = x << 16 | (hu->vals[k] & 0xf0) << 4 |
                            (DECBITS - (i + 1 + v)) | 128;
                    } else
                        x = v << 16 | (hu->vals[k] & 0xf0) << 4 |
                            (DECBITS - (i + 1));
                    hu->llvals[c | d] = x;
                }
            }
            code++;
            k++;
        }
        hu->maxcode[i] = code;
    }
    hu->maxcode[16] = 0x20000;        /* always terminate decode */
}

/****************************************************************/
/**************             idct                  ***************/
/****************************************************************/

#define ONE ((PREC)IFIX(1.))
#define S2  ((PREC)IFIX(0.382683432))
#define C2  ((PREC)IFIX(0.923879532))
#define C4  ((PREC)IFIX(0.707106781))

#define S22 ((PREC)IFIX(2 * 0.382683432))
#define C22 ((PREC)IFIX(2 * 0.923879532))
#define IC4 ((PREC)IFIX(1 / 0.707106781))

#define C3IC1 ((PREC)IFIX(0.847759065))        /* c3/c1 */
#define C5IC1 ((PREC)IFIX(0.566454497))        /* c5/c1 */
#define C7IC1 ((PREC)IFIX(0.198912367))        /* c7/c1 */

#define XPP(a,b) (t = a + b, b = a - b, a = t)
#define XMP(a,b) (t = a - b, b = a + b, a = t)
#define XPM(a,b) (t = a + b, b = b - a, a = t)

#define ROT(a,b,s,c) (  t = IMULT(a + b, s),      \
                        a = IMULT(a, c - s) + t,  \
                        b = IMULT(b, c + s) - t)

#define IDCT                \
(                           \
  XPP(t0, t1),              \
  XMP(t2, t3),              \
  t2 = IMULT(t2, IC4) - t3, \
  XPP(t0, t3),              \
  XPP(t1, t2),              \
  XMP(t4, t7),              \
  XPP(t5, t6),              \
  XMP(t5, t7),              \
  t5 = IMULT(t5, IC4),      \
  ROT(t4, t6, S22, C22),    \
  t6 -= t7,                 \
  t5 -= t6,                 \
  t4 -= t5,                 \
  XPP(t0, t7),              \
  XPP(t1, t6),              \
  XPP(t2, t5),              \
  XPP(t3, t4)               \
)

static unsigned char zig2[64] = {
     0,  2,  3,  9, 10, 20, 21, 35,
    14, 16, 25, 31, 39, 46, 50, 57,
     5,  7, 12, 18, 23, 33, 37, 48,
    27, 29, 41, 44, 52, 55, 59, 62,
    15, 26, 30, 40, 45, 51, 56, 58,
     1,  4,  8, 11, 19, 22, 34, 36,
    28, 42, 43, 53, 54, 60, 61, 63,
     6, 13, 17, 24, 32, 38, 47, 49
};

static void idct(int *in, int *out, PREC * quant, PREC off, int max)
{
    PREC t0, t1, t2, t3, t4, t5, t6, t7, t;
    PREC tmp[64], *tmpp;
    int i, j;
    unsigned char *zig2p;

    t0 = off;
    if (max == 1) {
        t0 += in[0] * quant[0];
        for (i = 0; i < 64; i++)
            out[i] = ITOINT(t0);
        return;
    }
    zig2p = zig2;
    tmpp = tmp;
    for (i = 0; i < 8; i++) {
        j = *zig2p++;
        t0 += in[j] * quant[j];
        j = *zig2p++;
        t5 = in[j] * quant[j];
        j = *zig2p++;
        t2 = in[j] * quant[j];
        j = *zig2p++;
        t7 = in[j] * quant[j];
        j = *zig2p++;
        t1 = in[j] * quant[j];
        j = *zig2p++;
        t4 = in[j] * quant[j];
        j = *zig2p++;
        t3 = in[j] * quant[j];
        j = *zig2p++;
        t6 = in[j] * quant[j];
        IDCT;
        tmpp[0 * 8] = t0;
        tmpp[1 * 8] = t1;
        tmpp[2 * 8] = t2;
        tmpp[3 * 8] = t3;
        tmpp[4 * 8] = t4;
        tmpp[5 * 8] = t5;
        tmpp[6 * 8] = t6;
        tmpp[7 * 8] = t7;
        tmpp++;
        t0 = 0;
    }
    for (i = 0; i < 8; i++) {
        t0 = tmp[8 * i + 0];
        t1 = tmp[8 * i + 1];
        t2 = tmp[8 * i + 2];
        t3 = tmp[8 * i + 3];
        t4 = tmp[8 * i + 4];
        t5 = tmp[8 * i + 5];
        t6 = tmp[8 * i + 6];
        t7 = tmp[8 * i + 7];
        IDCT;
        out[8 * i + 0] = ITOINT(t0);
        out[8 * i + 1] = ITOINT(t1);
        out[8 * i + 2] = ITOINT(t2);
        out[8 * i + 3] = ITOINT(t3);
        out[8 * i + 4] = ITOINT(t4);
        out[8 * i + 5] = ITOINT(t5);
        out[8 * i + 6] = ITOINT(t6);
        out[8 * i + 7] = ITOINT(t7);
    }
}

static unsigned char zig[64] = {
     0,  1,  5,  6, 14, 15, 27, 28,
     2,  4,  7, 13, 16, 26, 29, 42,
     3,  8, 12, 17, 25, 30, 41, 43,
     9, 11, 18, 24, 31, 40, 44, 53,
    10, 19, 23, 32, 39, 45, 52, 54,
    20, 22, 33, 38, 46, 51, 55, 60,
    21, 34, 37, 47, 50, 56, 59, 61,
    35, 36, 48, 49, 57, 58, 62, 63
};

static PREC aaidct[8] = {
    IFIX(0.3535533906), IFIX(0.4903926402),
    IFIX(0.4619397663), IFIX(0.4157348062),
    IFIX(0.3535533906), IFIX(0.2777851165),
    IFIX(0.1913417162), IFIX(0.0975451610)
};


static void idctqtab(unsigned char *qin, PREC * qout)
{
    int i, j;

    for (i = 0; i < 8; i++)
        for (j = 0; j < 8; j++)
            qout[zig[i * 8 + j]] = qin[zig[i * 8 + j]] *
                IMULT(aaidct[i], aaidct[j]);
}

static void scaleidctqtab(PREC * q, PREC sc)
{
    int i;

    for (i = 0; i < 64; i++)
        q[i] = IMULT(q[i], sc);
}

/****************************************************************/
/**************          color decoder            ***************/
/****************************************************************/

#define ROUND

/*
 * YCbCr Color transformation:
 *
 * y:0..255   Cb:-128..127   Cr:-128..127
 *
 *      R = Y                + 1.40200 * Cr
 *      G = Y - 0.34414 * Cb - 0.71414 * Cr
 *      B = Y + 1.77200 * Cb
 *
 * =>
 *      Cr *= 1.40200;
 *      Cb *= 1.77200;
 *      Cg = 0.19421 * Cb + .50937 * Cr;
 *      R = Y + Cr;
 *      G = Y - Cg;
 *      B = Y + Cb;
 *
 * =>
 *      Cg = (50 * Cb + 130 * Cr + 128) >> 8;
 */

static void initcol(PREC q[][64])
{
    scaleidctqtab(q[1], IFIX(1.77200));
    scaleidctqtab(q[2], IFIX(1.40200));
}

/* This is optimized for the stupid sun SUNWspro compiler. */
#define STORECLAMP(a,x)                          \
(                                                \
  (a) = (x),                                     \
  (unsigned int)(x) >= 256 ?                     \
    ((a) = (x) < 0 ? 0 : 255)                    \
  :                                              \
    0                                            \
)

#define CLAMP(x) ((unsigned int)(x) >= 256 ? ((x) < 0 ? 0 : 255) : (x))

#ifdef ROUND

#define CBCRCG(yin, xin)                         \
(                                                \
  cb = outc[0 +yin*8+xin],                       \
  cr = outc[64+yin*8+xin],                       \
  cg = (50 * cb + 130 * cr + 128) >> 8           \
)

#else

#define CBCRCG(yin, xin)                         \
(                                                \
  cb = outc[0 +yin*8+xin],                       \
  cr = outc[64+yin*8+xin],                       \
  cg = (3 * cb + 8 * cr) >> 4                    \
)

#endif

#ifdef __LITTLE_ENDIAN
#define PIC(yin, xin, p, xout)                   \
(                                                \
  y = outy[(yin) * 8 + xin],                     \
  STORECLAMP(p[(xout) * 3 + 2], y + cr),         \
  STORECLAMP(p[(xout) * 3 + 1], y - cg),         \
  STORECLAMP(p[(xout) * 3 + 0], y + cb)          \
)
#else
#define PIC(yin, xin, p, xout)                   \
(                                                \
  y = outy[(yin) * 8 + xin],                     \
  STORECLAMP(p[(xout) * 3 + 0], y + cr),         \
  STORECLAMP(p[(xout) * 3 + 1], y - cg),         \
  STORECLAMP(p[(xout) * 3 + 2], y + cb)          \
)
#endif

#ifdef __LITTLE_ENDIAN
#define PIC_16(yin, xin, p, xout, add)           \
(                                                \
  y = outy[(yin) * 8 + xin],                     \
  y = ((CLAMP(y + cr + add*2+1) & 0xf8) <<  8) | \
      ((CLAMP(y - cg + add    ) & 0xfc) <<  3) | \
      ((CLAMP(y + cb + add*2+1)       ) >>  3),  \
  p[(xout) * 2 + 0] = y & 0xff,                  \
  p[(xout) * 2 + 1] = y >> 8                     \
)
#else
#ifdef CONFIG_PPC
#define PIC_16(yin, xin, p, xout, add)           \
(                                                \
  y = outy[(yin) * 8 + xin],                     \
  y = ((CLAMP(y + cr + add*2+1) & 0xf8) <<  7) | \
      ((CLAMP(y - cg + add*2+1) & 0xf8) <<  2) | \
      ((CLAMP(y + cb + add*2+1)       ) >>  3),  \
  p[(xout) * 2 + 0] = y >> 8,                    \
  p[(xout) * 2 + 1] = y & 0xff                   \
)
#else
#define PIC_16(yin, xin, p, xout, add)           \
(                                                \
  y = outy[(yin) * 8 + xin],                     \
  y = ((CLAMP(y + cr + add*2+1) & 0xf8) <<  8) | \
      ((CLAMP(y - cg + add    ) & 0xfc) <<  3) | \
      ((CLAMP(y + cb + add*2+1)       ) >>  3),  \
  p[(xout) * 2 + 0] = y >> 8,                    \
  p[(xout) * 2 + 1] = y & 0xff                   \
)
#endif
#endif

#define PIC_32(yin, xin, p, xout)               \
(                                               \
  y = outy[(yin) * 8 + xin],                    \
  STORECLAMP(p[(xout) * 4 + 0], y + cr),        \
  STORECLAMP(p[(xout) * 4 + 1], y - cg),        \
  STORECLAMP(p[(xout) * 4 + 2], y + cb),        \
  p[(xout) * 4 + 3] = 0                         \
)

#define PIC221111(xin)                                              \
(                                                                   \
  CBCRCG(0, xin),                                                   \
  PIC(xin / 4 * 8 + 0, (xin & 3) * 2 + 0, pic0, xin * 2 + 0),       \
  PIC(xin / 4 * 8 + 0, (xin & 3) * 2 + 1, pic0, xin * 2 + 1),       \
  PIC(xin / 4 * 8 + 1, (xin & 3) * 2 + 0, pic1, xin * 2 + 0),       \
  PIC(xin / 4 * 8 + 1, (xin & 3) * 2 + 1, pic1, xin * 2 + 1)        \
)

#define PIC221111_16(xin)                                           \
(                                                                   \
  CBCRCG(0, xin),                                                   \
  PIC_16(xin / 4 * 8 + 0, (xin & 3) * 2 + 0, pic0, xin * 2 + 0, 3), \
  PIC_16(xin / 4 * 8 + 0, (xin & 3) * 2 + 1, pic0, xin * 2 + 1, 0), \
  PIC_16(xin / 4 * 8 + 1, (xin & 3) * 2 + 0, pic1, xin * 2 + 0, 1), \
  PIC_16(xin / 4 * 8 + 1, (xin & 3) * 2 + 1, pic1, xin * 2 + 1, 2)  \
)

#define PIC221111_32(xin)                                           \
(                                                                   \
  CBCRCG(0, xin),                                                   \
  PIC_32(xin / 4 * 8 + 0, (xin & 3) * 2 + 0, pic0, xin * 2 + 0),    \
  PIC_32(xin / 4 * 8 + 0, (xin & 3) * 2 + 1, pic0, xin * 2 + 1),    \
  PIC_32(xin / 4 * 8 + 1, (xin & 3) * 2 + 0, pic1, xin * 2 + 0),    \
  PIC_32(xin / 4 * 8 + 1, (xin & 3) * 2 + 1, pic1, xin * 2 + 1)     \
)

static void col221111(int *out, unsigned char *pic, int width)
{
    int i, j, k;
    unsigned char *pic0, *pic1;
    int *outy, *outc;
    int cr, cg, cb, y;

    pic0 = pic;
    pic1 = pic + width;
    outy = out;
    outc = out + 64 * 4;
    for (i = 2; i > 0; i--) {
        for (j = 4; j > 0; j--) {
            for (k = 0; k < 8; k++) {
                PIC221111(k);
            }
            outc += 8;
            outy += 16;
            pic0 += 2 * width;
            pic1 += 2 * width;
        }
        outy += 64 * 2 - 16 * 4;
    }
}

static void col221111_16(int *out, unsigned char *pic, int width)
{
    int i, j, k;
    unsigned char *pic0, *pic1;
    int *outy, *outc;
    int cr, cg, cb, y;

    pic0 = pic;
    pic1 = pic + width;
    outy = out;
    outc = out + 64 * 4;
    for (i = 2; i > 0; i--) {
        for (j = 4; j > 0; j--) {
            for (k = 0; k < 8; k++) {
                PIC221111_16(k);
            }
            outc += 8;
            outy += 16;
            pic0 += 2 * width;
            pic1 += 2 * width;
        }
        outy += 64 * 2 - 16 * 4;
    }
}

static void col221111_32(int *out, unsigned char *pic, int width)
{
    int i, j, k;
    unsigned char *pic0, *pic1;
    int *outy, *outc;
    int cr, cg, cb, y;

    pic0 = pic;
    pic1 = pic + width;
    outy = out;
    outc = out + 64 * 4;
    for (i = 2; i > 0; i--) {
        for (j = 4; j > 0; j--) {
            for (k = 0; k < 8; k++) {
                PIC221111_32(k);
            }
            outc += 8;
            outy += 16;
            pic0 += 2 * width;
            pic1 += 2 * width;
        }
        outy += 64 * 2 - 16 * 4;
    }
}
