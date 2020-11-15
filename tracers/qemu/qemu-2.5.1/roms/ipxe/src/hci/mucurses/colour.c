#include <curses.h>

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

struct colour_pair {
	short fcol;
	short bcol;
};

static struct colour_pair cpairs[COLOUR_PAIRS] = {
	[0] = { COLOUR_WHITE, COLOUR_BLACK },
};

/**
 * Identify the RGB components of a given colour value
 *
 * @v colour	colour value
 * @v *red	address to store red component
 * @v *green	address to store green component
 * @v *blue	address to store blue component
 * @ret rc	return status code
 */
int colour_content ( short colour, short *red, short *green, short *blue ) {
	*red = ( ( colour & COLOUR_RED ) ? 1 : 0 );
	*green = ( ( colour & COLOUR_GREEN ) ? 1 : 0 );
	*blue = ( ( colour & COLOUR_BLUE ) ? 1 : 0 );
	return OK;
}

/**
 * Initialise colour pair
 *
 * @v pair	colour pair number
 * @v fcol	foreground colour
 * @v bcol	background colour
 */
int init_pair ( short pair, short fcol, short bcol ) {
	struct colour_pair *cpair;

	if ( ( pair < 1 ) || ( pair >= COLOUR_PAIRS ) )
		return ERR;
	
	cpair = &cpairs[pair];
	cpair->fcol = fcol;
	cpair->bcol = bcol;
	return OK;
}

/**
 * Get colours of colour pair
 *
 * @v pair	colour pair number
 * @ret fcol	foreground colour
 * @ret bcol	background colour
 */
int pair_content ( short pair, short *fcol, short *bcol ) {
	struct colour_pair *cpair;

	if ( ( pair < 0 ) || ( pair >= COLOUR_PAIRS ) )
		return ERR;
	
	cpair = &cpairs[pair];
	*fcol = cpair->fcol;
	*bcol = cpair->bcol;
	return OK;
}
