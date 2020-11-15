/*
 * Copyright (c) 2008-2009 Atheros Communications Inc.
 *
 * Modified for iPXE by Scott K Logan <logans@cottsay.net> July 2011
 * Original from Linux kernel 3.0.1
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef ATH_H
#define ATH_H

FILE_LICENCE ( BSD2 );

#include <unistd.h>
#include <ipxe/net80211.h>

/* This block of functions are from kernel.h v3.0.1 */
#define ARRAY_SIZE(arr)		(sizeof(arr) / sizeof((arr)[0]))
#define DIV_ROUND_UP(n,d)	(((n) + (d) - 1) / (d))
#define BITS_PER_BYTE		8
#define BITS_TO_LONGS(nr)	DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(long))
#define BIT(nr)			(1UL << (nr))

#define min(x, y) ({					\
	typeof(x) _min1 = (x);				\
	typeof(y) _min2 = (y);				\
	(void) (&_min1 == &_min2);			\
	_min1 < _min2 ? _min1 : _min2; })
#define max(x, y) ({					\
	typeof(x) _max1 = (x);				\
	typeof(y) _max2 = (y);				\
	(void) (&_max1 == &_max2);			\
	_max1 > _max2 ? _max1 : _max2; })
#define abs(x) ({					\
		long ret;				\
		if (sizeof(x) == sizeof(long)) {	\
			long __x = (x);			\
			ret = (__x < 0) ? -__x : __x;	\
		} else {				\
			int __x = (x);			\
			ret = (__x < 0) ? -__x : __x;	\
		}					\
		ret;					\
	})

#define ___constant_swab16(x) ((uint16_t)(			\
	(((uint16_t)(x) & (uint16_t)0x00ffU) << 8) |		\
	(((uint16_t)(x) & (uint16_t)0xff00U) >> 8)))
#define ___constant_swab32(x) ((uint32_t)(			\
	(((uint32_t)(x) & (uint32_t)0x000000ffUL) << 24) |	\
	(((uint32_t)(x) & (uint32_t)0x0000ff00UL) <<  8) |	\
	(((uint32_t)(x) & (uint32_t)0x00ff0000UL) >>  8) |	\
	(((uint32_t)(x) & (uint32_t)0xff000000UL) >> 24)))
#define __swab16(x) ___constant_swab16(x)
#define __swab32(x) ___constant_swab32(x)
#define swab16 __swab16
#define swab32 __swab32

static inline int32_t sign_extend32(uint32_t value, int index)
{
	uint8_t shift = 31 - index;
	return (int32_t)(value << shift) >> shift;
}

static inline u16 __get_unaligned_le16(const u8 *p)
{
	return p[0] | p[1] << 8;
}
static inline u32 __get_unaligned_le32(const u8 *p)
{
	return p[0] | p[1] << 8 | p[2] << 16 | p[3] << 24;
}
static inline u16 get_unaligned_le16(const void *p)
{
	return __get_unaligned_le16((const u8 *)p);
}
static inline u32 get_unaligned_le32(const void *p)
{
	return __get_unaligned_le32((const u8 *)p);
}
/* End Kernel Block */

/*
 * The key cache is used for h/w cipher state and also for
 * tracking station state such as the current tx antenna.
 * We also setup a mapping table between key cache slot indices
 * and station state to short-circuit node lookups on rx.
 * Different parts have different size key caches.  We handle
 * up to ATH_KEYMAX entries (could dynamically allocate state).
 */
#define	ATH_KEYMAX	        128     /* max key cache size we handle */

static const u8 ath_bcast_mac[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

struct ath_ani {
	int caldone;
	unsigned int longcal_timer;
	unsigned int shortcal_timer;
	unsigned int resetcal_timer;
	unsigned int checkani_timer;
	int timer;
};

struct ath_cycle_counters {
	u32 cycles;
	u32 rx_busy;
	u32 rx_frame;
	u32 tx_frame;
};

enum ath_device_state {
	ATH_HW_UNAVAILABLE,
	ATH_HW_INITIALIZED,
};

enum ath_bus_type {
	ATH_PCI,
	ATH_AHB,
	ATH_USB,
};

struct reg_dmn_pair_mapping {
	u16 regDmnEnum;
	u16 reg_5ghz_ctl;
	u16 reg_2ghz_ctl;
};

struct ath_regulatory {
	char alpha2[2];
	u16 country_code;
	u16 max_power_level;
	u32 tp_scale;
	u16 current_rd;
	u16 current_rd_ext;
	int16_t power_limit;
	struct reg_dmn_pair_mapping *regpair;
};

enum ath_crypt_caps {
	ATH_CRYPT_CAP_CIPHER_AESCCM		= BIT(0),
	ATH_CRYPT_CAP_MIC_COMBINED		= BIT(1),
};

struct ath_keyval {
	u8 kv_type;
	u8 kv_pad;
	u16 kv_len;
	u8 kv_val[16]; /* TK */
	u8 kv_mic[8]; /* Michael MIC key */
	u8 kv_txmic[8]; /* Michael MIC TX key (used only if the hardware
			 * supports both MIC keys in the same key cache entry;
			 * in that case, kv_mic is the RX key) */
};

enum ath_cipher {
	ATH_CIPHER_WEP = 0,
	ATH_CIPHER_AES_OCB = 1,
	ATH_CIPHER_AES_CCM = 2,
	ATH_CIPHER_CKIP = 3,
	ATH_CIPHER_TKIP = 4,
	ATH_CIPHER_CLR = 5,
	ATH_CIPHER_MIC = 127
};

/**
 * struct ath_ops - Register read/write operations
 *
 * @read: Register read
 * @multi_read: Multiple register read
 * @write: Register write
 * @enable_write_buffer: Enable multiple register writes
 * @write_flush: flush buffered register writes and disable buffering
 */
struct ath_ops {
	unsigned int (*read)(void *, u32 reg_offset);
	void (*multi_read)(void *, u32 *addr, u32 *val, u16 count);
	void (*write)(void *, u32 val, u32 reg_offset);
	void (*enable_write_buffer)(void *);
	void (*write_flush) (void *);
	u32 (*rmw)(void *, u32 reg_offset, u32 set, u32 clr);
};

struct ath_common;
struct ath_bus_ops;

struct ath_common {
	void *ah;
	void *priv;
	struct net80211_device *dev;
	int debug_mask;
	enum ath_device_state state;

	struct ath_ani ani;

	u16 cachelsz;
	u16 curaid;
	u8 macaddr[ETH_ALEN];
	u8 curbssid[ETH_ALEN];
	u8 bssidmask[ETH_ALEN];

	u8 tx_chainmask;
	u8 rx_chainmask;

	u32 rx_bufsize;

	u32 keymax;
	enum ath_crypt_caps crypt_caps;

	unsigned int clockrate;

	struct ath_cycle_counters cc_ani;
	struct ath_cycle_counters cc_survey;

	struct ath_regulatory regulatory;
	const struct ath_ops *ops;
	const struct ath_bus_ops *bus_ops;

	int btcoex_enabled;
};

struct io_buffer *ath_rxbuf_alloc(struct ath_common *common,
				u32 len,
				u32 *iob_addr);

void ath_hw_setbssidmask(struct ath_common *common);
int ath_hw_keyreset(struct ath_common *common, u16 entry);
void ath_hw_cycle_counters_update(struct ath_common *common);
int32_t ath_hw_get_listen_time(struct ath_common *common);

#endif /* ATH_H */
