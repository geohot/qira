#include <curses.h>

/** @file
 *
 * MuCurses window attribute functions
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/**
 * Get the background rendition attributes for a window
 *
 * @v *win	subject window
 * @ret ch	chtype rendition representation
 */
inline chtype getbkgd ( WINDOW *win ) {
	return win->attrs;
}

/**
 * Turn off attributes in a window
 *
 * @v win	subject window
 * @v attrs	attributes to enable
 * @ret rc	return status code
 */
int wattroff ( WINDOW *win, int attrs ) {
	win->attrs &= ~attrs;
	return OK;
}

/**
 * Turn on attributes in a window
 *
 * @v win	subject window
 * @v attrs	attributes to enable
 * @ret rc	return status code
 */
int wattron ( WINDOW *win, int attrs ) {
	win->attrs |= attrs;
	return OK;
}

/**
 * Set attributes in a window
 *
 * @v win	subject window
 * @v attrs	attributes to enable
 * @ret rc	return status code
 */
int wattrset ( WINDOW *win, int attrs ) {
	win->attrs = ( attrs | ( win->attrs & A_COLOR ) );
	return OK;
}

/**
 * Get attributes and colour pair information
 *
 * @v *win	window to obtain information from
 * @v *attrs	address in which to store attributes
 * @v *pair	address in which to store colour pair
 * @v *opts	undefined (for future implementation)
 * @ret rc	return status cude
 */
int wattr_get ( WINDOW *win, attr_t *attrs, short *pair, 
		void *opts __unused ) {
	*attrs = win->attrs & A_ATTRIBUTES;
	*pair = PAIR_NUMBER ( win->attrs );
	return OK;
}

/**
 * Turn off attributes in a window
 *
 * @v *win	subject window
 * @v attrs	attributes to toggle
 * @v *opts	undefined (for future implementation)
 * @ret rc	return status code
 */
int wattr_off ( WINDOW *win, attr_t attrs, 
		void *opts __unused ) {
	wattroff( win, attrs );
	return OK;
}

/**
 * Turn on attributes in a window
 *
 * @v *win	subject window
 * @v attrs	attributes to toggle
 * @v *opts	undefined (for future implementation)
 * @ret rc	return status code
 */
int wattr_on ( WINDOW *win, attr_t attrs, 
	       void *opts __unused ) {
	wattron( win, attrs );
	return OK;
}

/**
 * Set attributes and colour pair information in a window
 *
 * @v *win	subject window
 * @v attrs	attributes to set
 * @v cpair	colour pair to set
 * @v *opts	undefined (for future implementation)
 * @ret rc	return status code
 */
int wattr_set ( WINDOW *win, attr_t attrs, short cpair, 
		void *opts __unused ) {
	wattrset( win, attrs | COLOUR_PAIR ( cpair ) );
	return OK;
}

/**
 * Set colour pair for a window
 *
 * @v *win			subject window
 * @v colour_pair_number	colour pair integer
 * @v *opts			undefined (for future implementation)
 * @ret rc			return status code
 */
int wcolour_set ( WINDOW *win, short colour_pair_number, 
		  void *opts __unused ) {
	if ( ( unsigned short )colour_pair_number > COLOUR_PAIRS )
		return ERR;

	win->attrs = ( ( win->attrs & A_ATTRIBUTES ) |
		       COLOUR_PAIR ( colour_pair_number ) );
	return OK;
}

