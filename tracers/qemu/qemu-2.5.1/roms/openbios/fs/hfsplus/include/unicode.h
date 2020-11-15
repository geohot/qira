/*
 *  linux/fs/hfsplus/unicode.c
 *
 * Copyright (C) 1999-2000  Brad Boyer (flar@pants.nu)
 * This file may be distributed under the terms of the GNU Public License.
 *
 * The routines found here convert hfs-unicode string into ascii Strings
 * and vice versa.  And the correct comparison between Strings.
 */

/* convert the asci string astr into a unicode string given by ustr.
 *
 * returns actual length of convertet string.
 */

int unicode_asc2uni(hfsp_unistr255 *ustr, const char *astr);

/* Convert an unicode string ustr to a ascii string astr of given maximum len
 *
 * returns actual length of convertet string.
 */

int unicode_uni2asc(char *astr, const hfsp_unistr255 *ustr, int maxlen);

/* similar to strcmp for unicode, pascal strings */

SInt32 fast_unicode_compare (const hfsp_unistr255 *ustr1,
			     const hfsp_unistr255 *ustr2);
