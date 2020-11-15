#ifndef _IPXE_EDITSTRING_H
#define _IPXE_EDITSTRING_H

/** @file
 *
 * Editable strings
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/** An editable string */
struct edit_string {
	/** Buffer for string */
	char *buf;
	/** Size of buffer (including terminating NUL) */
	size_t len;
	/** Cursor position */
	unsigned int cursor;

	/* The following items are the edit history */

	/** Last cursor position */
	unsigned int last_cursor;
	/** Start of modified portion of string */
	unsigned int mod_start;
	/** End of modified portion of string */
	unsigned int mod_end;
};

/**
 * Initialise editable string
 *
 * @v string		Editable string
 * @v buf		Buffer for string
 * @v len		Length of buffer
 */
static inline void init_editstring ( struct edit_string *string, char *buf,
				     size_t len ) {
	string->buf = buf;
	string->len = len;
}

extern void replace_string ( struct edit_string *string,
			     const char *replacement ) __nonnull;
extern int edit_string ( struct edit_string *string, int key ) __nonnull;

#endif /* _IPXE_EDITSTRING_H */
