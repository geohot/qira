/*
 * Copyright (c) 2009 Atheros Communications Inc.
 * Copyright (c) 2010 Bruno Randolf <br1@einfach.org>
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

#include "ath.h"
#include "reg.h"

#define REG_READ			(common->ops->read)
#define REG_WRITE(_ah, _reg, _val)	(common->ops->write)(_ah, _val, _reg)
#define ENABLE_REGWRITE_BUFFER(_ah)			\
	if (common->ops->enable_write_buffer)		\
		common->ops->enable_write_buffer((_ah));

#define REGWRITE_BUFFER_FLUSH(_ah)			\
	if (common->ops->write_flush)			\
		common->ops->write_flush((_ah));


#define IEEE80211_WEP_NKID      4       /* number of key ids */

/************************/
/* Key Cache Management */
/************************/

int ath_hw_keyreset(struct ath_common *common, u16 entry)
{
	u32 keyType;
	void *ah = common->ah;

	if (entry >= common->keymax) {
		DBG("ath: keycache entry %d out of range\n", entry);
		return 0;
	}

	keyType = REG_READ(ah, AR_KEYTABLE_TYPE(entry));

	ENABLE_REGWRITE_BUFFER(ah);

	REG_WRITE(ah, AR_KEYTABLE_KEY0(entry), 0);
	REG_WRITE(ah, AR_KEYTABLE_KEY1(entry), 0);
	REG_WRITE(ah, AR_KEYTABLE_KEY2(entry), 0);
	REG_WRITE(ah, AR_KEYTABLE_KEY3(entry), 0);
	REG_WRITE(ah, AR_KEYTABLE_KEY4(entry), 0);
	REG_WRITE(ah, AR_KEYTABLE_TYPE(entry), AR_KEYTABLE_TYPE_CLR);
	REG_WRITE(ah, AR_KEYTABLE_MAC0(entry), 0);
	REG_WRITE(ah, AR_KEYTABLE_MAC1(entry), 0);

	if (keyType == AR_KEYTABLE_TYPE_TKIP) {
		u16 micentry = entry + 64;

		REG_WRITE(ah, AR_KEYTABLE_KEY0(micentry), 0);
		REG_WRITE(ah, AR_KEYTABLE_KEY1(micentry), 0);
		REG_WRITE(ah, AR_KEYTABLE_KEY2(micentry), 0);
		REG_WRITE(ah, AR_KEYTABLE_KEY3(micentry), 0);
		if (common->crypt_caps & ATH_CRYPT_CAP_MIC_COMBINED) {
			REG_WRITE(ah, AR_KEYTABLE_KEY4(micentry), 0);
			REG_WRITE(ah, AR_KEYTABLE_TYPE(micentry),
				  AR_KEYTABLE_TYPE_CLR);
		}

	}

	REGWRITE_BUFFER_FLUSH(ah);

	return 1;
}
