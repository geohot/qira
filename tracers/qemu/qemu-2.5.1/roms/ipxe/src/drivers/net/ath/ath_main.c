/*
 * Copyright (c) 2009 Atheros Communications Inc.
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

#include <ipxe/io.h>

#include "ath.h"

struct io_buffer *ath_rxbuf_alloc(struct ath_common *common,
				u32 len,
				u32 *iob_addr)
{
	struct io_buffer *iob;
	u32 off;

	/*
	 * Cache-line-align.  This is important (for the
	 * 5210 at least) as not doing so causes bogus data
	 * in rx'd frames.
	 */

	/* Note: the kernel can allocate a value greater than
	 * what we ask it to give us. We really only need 4 KB as that
	 * is this hardware supports and in fact we need at least 3849
	 * as that is the MAX AMSDU size this hardware supports.
	 * Unfortunately this means we may get 8 KB here from the
	 * kernel... and that is actually what is observed on some
	 * systems :( */
	iob = alloc_iob(len + common->cachelsz - 1);
	if (iob != NULL) {
		*iob_addr = virt_to_bus(iob->data);
		off = ((unsigned long) iob->data) % common->cachelsz;
		if (off != 0)
		{
			iob_reserve(iob, common->cachelsz - off);
			*iob_addr += common->cachelsz - off;
		}
	} else {
		DBG("ath: iobuffer alloc of size %d failed\n", len);
		return NULL;
	}

	return iob;
}
