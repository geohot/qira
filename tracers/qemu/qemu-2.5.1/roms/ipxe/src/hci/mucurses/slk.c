#include <curses.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "mucurses.h"
#include "cursor.h"

/** @file
 *
 * Soft label key functions
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#define MIN_SPACE_SIZE 2

#define SLK_MAX_LABEL_LEN 8

#define SLK_MAX_NUM_LABELS 12

#define SLK_MAX_NUM_SPACES 2

struct _softlabel {
	// label string
	char label[SLK_MAX_LABEL_LEN];
	/* Format of soft label 
	   0: left justify
	   1: centre justify
	   2: right justify
	 */
	unsigned int fmt;
};

struct _softlabelkeys {
	struct _softlabel fkeys[SLK_MAX_NUM_LABELS];
	attr_t attrs;
	/* Soft label layout format
	   0: 3-2-3
	   1: 4-4
	   2: 4-4-4
	   3: 4-4-4 with index line
	*/
	unsigned int fmt;
	unsigned int max_label_len;
	unsigned int maj_space_len;
	unsigned int num_labels;
	unsigned int num_spaces;
	unsigned int spaces[SLK_MAX_NUM_SPACES];
	struct cursor_pos saved_cursor;
	attr_t saved_attrs;
	short saved_pair;
};

static struct _softlabelkeys *slks;

/*
  I either need to break the primitives here, or write a collection of
  functions specifically for SLKs that directly access the screen
  functions - since this technically isn't part of stdscr, I think
  this should be ok...
 */

static void _enter_slk ( void ) {
	_store_curs_pos ( stdscr, &slks->saved_cursor );
	wattr_get ( stdscr, &slks->saved_attrs, &slks->saved_pair, NULL );
	LINES++;
	wmove ( stdscr, LINES, 0 );
	wattrset ( stdscr, slks->attrs );
}

static void _leave_slk ( void ) {
	LINES--;
	wattr_set ( stdscr, slks->saved_attrs, slks->saved_pair, NULL );
	_restore_curs_pos ( stdscr, &slks->saved_cursor );
}

static void _print_label ( struct _softlabel sl ) {
	int space_ch;
	char str[SLK_MAX_LABEL_LEN + 1];

	assert ( slks->max_label_len <= SLK_MAX_LABEL_LEN );
	space_ch = ' ';

	// protect against gaps in the soft label keys array
	if ( sl.label == NULL ) {
		memset( str, space_ch, (size_t)(slks->max_label_len) );
	} else {
		/* we need to pad the label with varying amounts of leading
		   pad depending on the format of the label */
		if ( sl.fmt == 1 ) {
			memset( str, space_ch, 
				(size_t)(slks->max_label_len 
					 - strlen(sl.label)) / 2 );
		}
		if ( sl.fmt == 2 ) {
			memset( str, space_ch,
				(size_t)(slks->max_label_len 
					 - strlen(sl.label)) );
		}
		strcat(str,sl.label);
		
		// post-padding
		memset(str+strlen(str), space_ch,
		       (size_t)(slks->max_label_len - strlen(str)) );
	}

	// print the formatted label
	_wputstr ( stdscr, str, NOWRAP, slks->max_label_len );
}

/**
 * Return the attribute used for the soft function keys
 *
 * @ret attrs	the current attributes of the soft function keys
 */
attr_t slk_attr ( void ) {
	return ( slks == NULL ? 0 : slks->attrs );
}

/**
 * Turn off soft function key attributes
 *
 * @v attrs	attribute bit mask
 * @ret rc	return status code
 */
int slk_attroff ( const chtype attrs ) {
	if ( slks == NULL ) 
		return ERR;
	slks->attrs &= ~( attrs & A_ATTRIBUTES );
	return OK;
}

/**
 * Turn on soft function key attributes
 *
 * @v attrs	attribute bit mask
 * @ret rc	return status code
 */
int slk_attron ( const chtype attrs ) {
	if ( slks == NULL )
		return ERR;
	slks->attrs |= ( attrs & A_ATTRIBUTES );
	return OK;
}

/**
 * Set soft function key attributes
 *
 * @v attrs	attribute bit mask
 * @ret rc	return status code
 */
int slk_attrset ( const chtype attrs ) {
	if ( slks == NULL ) 
		return ERR;
	slks->attrs = ( attrs & A_ATTRIBUTES );
	return OK;
}

/**
 * Turn off soft function key attributes
 *
 * @v attrs	attribute bit mask
 * @v *opts	undefined (for future implementation)
 * @ret rc	return status code
 */
int slk_attr_off ( const attr_t attrs, void *opts __unused ) {
	return slk_attroff( attrs );
}

/**
 * Turn on soft function key attributes
 *
 * @v attrs	attribute bit mask
 * @v *opts	undefined (for future implementation)
 * @ret rc	return status code
 */
int slk_attr_on ( attr_t attrs, void *opts __unused ) {
	return slk_attron( attrs );
}

/**
 * Set soft function key attributes
 *
 * @v attrs			attribute bit mask
 * @v colour_pair_number	colour pair integer
 * @v *opts			undefined (for future implementation)
 * @ret rc			return status code
 */
int slk_attr_set ( const attr_t attrs, short colour_pair_number,
		   void *opts __unused ) {
	if ( slks == NULL ) 
		return ERR;

	if ( ( unsigned short )colour_pair_number > COLORS )
		return ERR;

	slks->attrs = ( (unsigned short)colour_pair_number << CPAIR_SHIFT ) |
		( attrs & A_ATTRIBUTES );
	return OK;
}

/**
 * Clear the soft function key labels from the screen
 *
 * @ret rc	return status code
 */
int slk_clear ( void ) {
	if ( slks == NULL )
		return ERR;

	_enter_slk();
	wclrtoeol ( stdscr );
	_leave_slk();

	return OK;
}

/**
 * Set soft label colour pair
 */
int slk_colour ( short colour_pair_number ) {
	if ( slks == NULL ) 
		return ERR;
	if ( ( unsigned short )colour_pair_number > COLORS )
		return ERR;

	slks->attrs = ( (unsigned short)colour_pair_number << CPAIR_SHIFT )
		| ( slks->attrs & A_ATTRIBUTES );

	return OK;
}

/**
 * Initialise the soft function keys
 *
 * @v fmt	format of keys
 * @ret rc	return status code
 */
int slk_init ( int fmt ) {
	unsigned short nmaj, nmin, nblocks, available_width;

	if ( (unsigned)fmt > 3 ) {
		return ERR;
	}

	/* There seems to be no API call to free this data structure... */
	if ( ! slks )
		slks = calloc(1,sizeof(*slks));
	if ( ! slks )
		return ERR;

	slks->attrs = A_DEFAULT;
	slks->fmt = fmt;
	switch(fmt) {
	case 0:
		nblocks = 8; nmaj = 2; nmin = 5;
		slks->spaces[0] = 2; slks->spaces[1] = 4;
		break;
	case 1:
		nblocks = 8; nmaj = 1; nmin = 6;
		slks->spaces[0] = 3;
		break;
	case 2:
		// same allocations as format 3
	case 3:
		nblocks = 12; nmaj = 2; nmin = 9;
		slks->spaces[0] = 3; slks->spaces[1] = 7;
		break;
	default:
		nblocks = 0; nmaj = 0; nmin = 0;
		break;
	}

	// determine maximum label length and major space size
	available_width = COLS - ( ( MIN_SPACE_SIZE * nmaj ) + nmin );
	slks->max_label_len = available_width / nblocks;
	slks->maj_space_len = MIN_SPACE_SIZE + 
		( available_width % nblocks ) / nmaj;
	slks->num_spaces = nmaj;
	slks->num_labels = nblocks;

	// strip a line from the screen
	LINES -= 1;

	return OK;
}

/**
 * Return the label for the specified soft key
 *
 * @v labnum	soft key identifier
 * @ret label	return label
 */
char* slk_label ( int labnum ) {
	if ( slks == NULL ) 
		return NULL;

	return slks->fkeys[labnum].label;
}

/**
 * Restore soft function key labels to the screen
 *
 * @ret rc	return status code
 */
int slk_restore ( void ) {
	unsigned int i, j, pos_x,
		*next_space, *last_space;
	chtype space_ch;

	if ( slks == NULL )
		return ERR;

	pos_x = 0;

	_enter_slk();

	space_ch = (chtype)' ' | slks->attrs;
	next_space = &(slks->spaces[0]);
	last_space = &(slks->spaces[slks->num_spaces-1]);

	for ( i = 0; i < slks->num_labels ; i++ ) {
		_print_label( slks->fkeys[i] );
		pos_x += slks->max_label_len;

		if ( i == *next_space ) {
			for ( j = 0; j < slks->maj_space_len; j++, pos_x++ )
				_wputch ( stdscr, space_ch, NOWRAP );
			if ( next_space < last_space )
				next_space++;
		} else {
			if ( pos_x < COLS )
				_wputch ( stdscr, space_ch, NOWRAP );
			pos_x++;
		}
	}

	_leave_slk();

	return OK;
}

/**
 * Configure specified soft key
 *
 * @v labnum	soft label position to configure
 * @v *label	string to use as soft key label
 * @v fmt	justification format of label
 * @ret rc	return status code
 */
int slk_set ( int labnum, const char *label, int fmt ) {
	if ( slks == NULL ) 
		return ERR;
	if ( (unsigned short)labnum >= slks->num_labels )
		return ERR;
	if ( (unsigned short)fmt >= 3 )
		return ERR;

	strncpy(slks->fkeys[labnum].label, label,
		sizeof(slks->fkeys[labnum].label));
	slks->fkeys[labnum].fmt = fmt;

	return OK;
}
