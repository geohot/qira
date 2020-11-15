#ifndef _READLINE_H
#define _READLINE_H

/** @file
 *
 * Minmal readline
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/** A readline history entry */
struct readline_history_entry {
	/** Persistent copy of string */
	char *string;
	/** Temporary copy of string
	 *
	 * The temporary copy exists only during the call to
	 * readline().
	 */
	char *temp;
};

/** Maximum depth of a readline history buffer
 *
 * Must be one less than a power of two.
 */
#define READLINE_HISTORY_MAX_DEPTH ( ( 1 << 3 ) - 1 )

/** A readline history buffer */
struct readline_history {
	/** History entries
	 *
	 * This is a circular buffer, with entries in chronological
	 * order.  The "next" entry is always empty except during a
	 * call to readline().
	 */
	struct readline_history_entry entries[READLINE_HISTORY_MAX_DEPTH + 1];
	/** Position of next entry within buffer
	 *
	 * This is incremented monotonically each time an entry is
	 * added to the buffer.
	 */
	unsigned int next;
	/** Current depth within history buffer
	 *
	 * This is valid only during the call to readline()
	 */
	unsigned int depth;
};

extern void history_free ( struct readline_history *history );
extern int readline_history ( const char *prompt, const char *prefill,
			      struct readline_history *history, char **line );
extern char * __malloc readline ( const char *prompt );

#endif /* _READLINE_H */
