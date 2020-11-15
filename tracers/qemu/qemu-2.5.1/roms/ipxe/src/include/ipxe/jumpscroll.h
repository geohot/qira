#ifndef _IPXE_JUMPSCROLL_H
#define _IPXE_JUMPSCROLL_H

/** @file
 *
 * Jump scrolling
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/** A jump scroller */
struct jump_scroller {
	/** Maximum number of visible rows */
	unsigned int rows;
	/** Total number of items */
	unsigned int count;
	/** Currently selected item */
	unsigned int current;
	/** First visible item */
	unsigned int first;
};

/**
 * Check if jump scroller is currently on first page
 *
 * @v scroll		Jump scroller
 * @ret is_first	Scroller is currently on first page
 */
static inline int jump_scroll_is_first ( struct jump_scroller *scroll ) {

	return ( scroll->first == 0 );
}

/**
 * Check if jump scroller is currently on last page
 *
 * @v scroll		Jump scroller
 * @ret is_last		Scroller is currently on last page
 */
static inline int jump_scroll_is_last ( struct jump_scroller *scroll ) {

	return ( ( scroll->first + scroll->rows ) >= scroll->count );
}

extern int jump_scroll_key ( struct jump_scroller *scroll, int key );
extern int jump_scroll_move ( struct jump_scroller *scroll, int move );
extern int jump_scroll ( struct jump_scroller *scroll );

#endif /* _IPXE_JUMPSCROLL_H */
