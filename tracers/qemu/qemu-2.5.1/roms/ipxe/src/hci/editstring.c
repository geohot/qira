/*
 * Copyright (C) 2006 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * You can also choose to distribute this program under the terms of
 * the Unmodified Binary Distribution Licence (as given in the file
 * COPYING.UBDL), provided that you have satisfied its requirements.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <assert.h>
#include <string.h>
#include <ctype.h>
#include <ipxe/keys.h>
#include <ipxe/editstring.h>

/** @file
 *
 * Editable strings
 *
 */

static void insert_delete ( struct edit_string *string, size_t delete_len,
                            const char *insert_text ) 
			    __attribute__ (( nonnull (1) ));
static void insert_character ( struct edit_string *string,
                               unsigned int character ) __nonnull;
static void delete_character ( struct edit_string *string ) __nonnull;
static void backspace ( struct edit_string *string ) __nonnull;
static void previous_word ( struct edit_string *string ) __nonnull;
static void kill_word ( struct edit_string *string ) __nonnull;
static void kill_sol ( struct edit_string *string ) __nonnull;
static void kill_eol ( struct edit_string *string ) __nonnull;

/**
 * Insert and/or delete text within an editable string
 *
 * @v string		Editable string
 * @v delete_len	Length of text to delete from current cursor position
 * @v insert_text	Text to insert at current cursor position, or NULL
 */
static void insert_delete ( struct edit_string *string, size_t delete_len,
			    const char *insert_text ) {
	size_t old_len, max_delete_len, insert_len, max_insert_len, new_len;

	/* Calculate lengths */
	old_len = strlen ( string->buf );
	assert ( string->cursor <= old_len );
	max_delete_len = ( old_len - string->cursor );
	if ( delete_len > max_delete_len )
		delete_len = max_delete_len;
	insert_len = ( insert_text ? strlen ( insert_text ) : 0 );
	max_insert_len = ( ( string->len - 1 ) - ( old_len - delete_len ) );
	if ( insert_len > max_insert_len )
		insert_len = max_insert_len;
	new_len = ( old_len - delete_len + insert_len );

	/* Fill in edit history */
	string->mod_start = string->cursor;
	string->mod_end = ( ( new_len > old_len ) ? new_len : old_len );

	/* Move data following the cursor */
	memmove ( ( string->buf + string->cursor + insert_len ),
		  ( string->buf + string->cursor + delete_len ),
		  ( max_delete_len + 1 - delete_len ) );

	/* Copy inserted text to cursor position */
	memcpy ( ( string->buf + string->cursor ), insert_text, insert_len );
	string->cursor += insert_len;
}

/**
 * Insert character at current cursor position
 *
 * @v string		Editable string
 * @v character		Character to insert
 */
static void insert_character ( struct edit_string *string,
			      unsigned int character ) {
	char insert_text[2] = { character, '\0' };
	insert_delete ( string, 0, insert_text );
}

/**
 * Delete character at current cursor position
 *
 * @v string		Editable string
 */
static void delete_character ( struct edit_string *string ) {
	insert_delete ( string, 1, NULL );
}

/**
 * Delete character to left of current cursor position
 *
 * @v string		Editable string
 */
static void backspace ( struct edit_string *string ) {
	if ( string->cursor > 0 ) {
		string->cursor--;
		delete_character ( string );
	}
}

/**
 * Move to start of previous word
 *
 * @v string		Editable string
 */
static void previous_word ( struct edit_string *string ) {
	while ( string->cursor &&
		isspace ( string->buf[ string->cursor - 1 ] ) ) {
		string->cursor--;
	}
	while ( string->cursor &&
		( ! isspace ( string->buf[ string->cursor - 1 ] ) ) ) {
		string->cursor--;
	}
}

/**
 * Delete to end of previous word
 *
 * @v string		Editable string
 */
static void kill_word ( struct edit_string *string ) {
	size_t old_cursor = string->cursor;
	previous_word ( string );
	insert_delete ( string, ( old_cursor - string->cursor ), NULL );
}

/**
 * Delete to start of line
 *
 * @v string		Editable string
 */
static void kill_sol ( struct edit_string *string ) {
	size_t old_cursor = string->cursor;
	string->cursor = 0;
	insert_delete ( string, old_cursor, NULL );
}

/**
 * Delete to end of line
 *
 * @v string		Editable string
 */
static void kill_eol ( struct edit_string *string ) {
	insert_delete ( string, ~( ( size_t ) 0 ), NULL );
}

/**
 * Replace editable string
 *
 * @v string		Editable string
 * @v replacement	Replacement string
 */
void replace_string ( struct edit_string *string, const char *replacement ) {
	string->cursor = 0;
	insert_delete ( string, ~( ( size_t ) 0 ), replacement );
}

/**
 * Edit editable string
 *
 * @v string		Editable string
 * @v key		Key pressed by user
 * @ret key		Key returned to application, or zero
 *
 * Handles keypresses and updates the content of the editable string.
 * Basic line editing facilities (delete/insert/cursor) are supported.
 * If edit_string() understands and uses the keypress it will return
 * zero, otherwise it will return the original key.
 *
 * This function does not update the display in any way.
 *
 * The string's edit history will be updated to allow the caller to
 * efficiently bring the display into sync with the string content.
 */
int edit_string ( struct edit_string *string, int key ) {
	int retval = 0;
	size_t len = strlen ( string->buf );

	/* Prepare edit history */
	string->last_cursor = string->cursor;
	string->mod_start = string->cursor;
	string->mod_end = string->cursor;

	/* Interpret key */
	if ( ( key >= 0x20 ) && ( key <= 0x7e ) ) {
		/* Printable character; insert at current position */
		insert_character ( string, key );
	} else switch ( key ) {
	case KEY_BACKSPACE:
		/* Backspace */
		backspace ( string );
		break;
	case KEY_DC:
	case CTRL_D:
		/* Delete character */
		delete_character ( string );
		break;
	case CTRL_W:
		/* Delete word */
		kill_word ( string );
		break;
	case CTRL_U:
		/* Delete to start of line */
		kill_sol ( string );
		break;
	case CTRL_K:
		/* Delete to end of line */
		kill_eol ( string );
		break;
	case KEY_HOME:
	case CTRL_A:
		/* Start of line */
		string->cursor = 0;
		break;
	case KEY_END:
	case CTRL_E:
		/* End of line */
		string->cursor = len;
		break;
	case KEY_LEFT:
	case CTRL_B:
		/* Cursor left */
		if ( string->cursor > 0 )
			string->cursor--;
		break;
	case KEY_RIGHT:
	case CTRL_F:
		/* Cursor right */
		if ( string->cursor < len )
			string->cursor++;
		break;
	default:
		retval = key;
		break;
	}

	return retval;
}
