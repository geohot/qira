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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <ipxe/console.h>
#include <ipxe/keys.h>
#include <ipxe/editstring.h>
#include <readline/readline.h>

/** @file
 *
 * Minimal readline
 *
 */

#define READLINE_MAX 256

/**
 * Synchronise console with edited string
 *
 * @v string		Editable string
 */
static void sync_console ( struct edit_string *string ) {
	unsigned int mod_start = string->mod_start;
	unsigned int mod_end = string->mod_end;
	unsigned int cursor = string->last_cursor;
	size_t len = strlen ( string->buf );

	/* Expand region back to old cursor position if applicable */
	if ( mod_start > string->last_cursor )
		mod_start = string->last_cursor;

	/* Expand region forward to new cursor position if applicable */
	if ( mod_end < string->cursor )
		mod_end = string->cursor;

	/* Backspace to start of region */
	while ( cursor > mod_start ) {
		putchar ( '\b' );
		cursor--;
	}

	/* Print modified region */
	while ( cursor < mod_end ) {
		putchar ( ( cursor >= len ) ? ' ' : string->buf[cursor] );
		cursor++;
	}

	/* Backspace to new cursor position */
	while ( cursor > string->cursor ) {
		putchar ( '\b' );
		cursor--;
	}
}

/**
 * Locate history entry
 *
 * @v history		History buffer
 * @v depth		Depth within history buffer
 * @ret entry		History entry
 */
static struct readline_history_entry *
history_entry ( struct readline_history *history, unsigned int depth ) {
	unsigned int offset;

	offset = ( ( history->next - depth ) %
		   ( sizeof ( history->entries ) /
		     sizeof ( history->entries[0] ) ) );
	return &history->entries[offset];
}

/**
 * Read string from history buffer
 *
 * @v history		History buffer
 * @v depth		Depth within history buffer
 * @ret string		String
 */
static const char * history_fetch ( struct readline_history *history,
				    unsigned int depth ) {
	struct readline_history_entry *entry;

	/* Return the temporary copy if it exists, otherwise return
	 * the persistent copy.
	 */
	entry = history_entry ( history, depth );
	return ( entry->temp ? entry->temp : entry->string );
}

/**
 * Write temporary string copy to history buffer
 *
 * @v history		History buffer
 * @v depth		Depth within history buffer
 * @v string		String
 */
static void history_store ( struct readline_history *history,
			    unsigned int depth, const char *string ) {
	struct readline_history_entry *entry;
	char *temp;

	/* Create temporary copy of string */
	temp = strdup ( string );
	if ( ! temp ) {
		/* Just discard the string; there's nothing we can do */
		DBGC ( history, "READLINE %p could not store string\n",
		       history );
		return;
	}

	/* Store temporary copy */
	entry = history_entry ( history, depth );
	free ( entry->temp );
	entry->temp = temp;
}

/**
 * Move to new history depth
 *
 * @v history		History buffer
 * @v offset		Offset by which to change depth
 * @v old_string	String (possibly modified) at current depth
 * @ret new_string	String at new depth, or NULL for no movement
 */
static const char * history_move ( struct readline_history *history,
				   int offset, const char *old_string ) {
	unsigned int new_depth = ( history->depth + offset );
	const char * new_string = history_fetch ( history, new_depth );

	/* Depth checks */
	if ( new_depth > READLINE_HISTORY_MAX_DEPTH )
		return NULL;
	if ( ! new_string )
		return NULL;

	/* Store temporary copy of old string at current depth */
	history_store ( history, history->depth, old_string );

	/* Update depth */
	history->depth = new_depth;

	/* Return new string */
	return new_string;
}

/**
 * Append new history entry
 *
 * @v history		History buffer
 * @v string		String
 */
static void history_append ( struct readline_history *history,
			     const char *string ) {
	struct readline_history_entry *entry;

	/* Store new entry */
	entry = history_entry ( history, 0 );
	assert ( entry->string == NULL );
	entry->string = strdup ( string );
	if ( ! entry->string ) {
		/* Just discard the string; there's nothing we can do */
		DBGC ( history, "READLINE %p could not append string\n",
		       history );
		return;
	}

	/* Increment history position */
	history->next++;

	/* Prepare empty "next" slot */
	entry = history_entry ( history, 0 );
	free ( entry->string );
	entry->string = NULL;
}

/**
 * Clean up history after editing
 *
 * @v history		History buffer
 */
static void history_cleanup ( struct readline_history *history ) {
	struct readline_history_entry *entry;
	unsigned int i;

	/* Discard any temporary strings */
	for ( i = 0 ; i < ( sizeof ( history->entries ) /
			    sizeof ( history->entries[0] ) ) ; i++ ) {
		entry = &history->entries[i];
		free ( entry->temp );
		entry->temp = NULL;
	}

	/* Reset depth */
	history->depth = 0;

	/* Sanity check */
	entry = history_entry ( history, 0 );
	assert ( entry->string == NULL );
}

/**
 * Free history buffer
 *
 * @v history		History buffer
 */
void history_free ( struct readline_history *history ) {
	struct readline_history_entry *entry;
	unsigned int i;

	/* Discard any temporary strings */
	for ( i = 0 ; i < ( sizeof ( history->entries ) /
			    sizeof ( history->entries[0] ) ) ; i++ ) {
		entry = &history->entries[i];
		assert ( entry->temp == NULL );
		free ( entry->string );
	}
}

/**
 * Read line from console (with history)
 *
 * @v prompt		Prompt string
 * @v prefill		Prefill string, or NULL for no prefill
 * @v history		History buffer, or NULL for no history
 * @ret line		Line read from console (excluding terminating newline)
 * @ret rc		Return status code
 *
 * The returned line is allocated with malloc(); the caller must
 * eventually call free() to release the storage.
 */
int readline_history ( const char *prompt, const char *prefill,
		       struct readline_history *history, char **line ) {
	char buf[READLINE_MAX];
	struct edit_string string;
	int key;
	int move_by;
	const char *new_string;
	int rc;

	/* Avoid returning uninitialised data on error */
	*line = NULL;

	/* Display prompt, if applicable */
	if ( prompt )
		printf ( "%s", prompt );

	/* Ensure cursor is visible */
	printf ( "\033[?25h" );

	/* Initialise editable string */
	memset ( &string, 0, sizeof ( string ) );
	init_editstring ( &string, buf, sizeof ( buf ) );
	buf[0] = '\0';

	/* Prefill string, if applicable */
	if ( prefill ) {
		replace_string ( &string, prefill );
		sync_console ( &string );
	}

	while ( 1 ) {
		/* Handle keypress */
		key = edit_string ( &string, getkey ( 0 ) );
		sync_console ( &string );
		move_by = 0;
		switch ( key ) {
		case CR:
		case LF:
			*line = strdup ( buf );
			rc = ( ( *line ) ? 0 : -ENOMEM );
			goto done;
		case CTRL_C:
			rc = -ECANCELED;
			goto done;
		case KEY_UP:
			move_by = 1;
			break;
		case KEY_DOWN:
			move_by = -1;
			break;
		default:
			/* Do nothing */
			break;
		}

		/* Handle history movement, if applicable */
		if ( move_by && history ) {
			new_string = history_move ( history, move_by, buf );
			if ( new_string ) {
				replace_string ( &string, new_string );
				sync_console ( &string );
			}
		}
	}

 done:
	putchar ( '\n' );
	if ( history ) {
		if ( *line && (*line)[0] )
			history_append ( history, *line );
		history_cleanup ( history );
	}
	assert ( ( rc == 0 ) ^ ( *line == NULL ) );
	return rc;
}

/**
 * Read line from console
 *
 * @v prompt		Prompt string
 * @ret line		Line read from console (excluding terminating newline)
 *
 * The returned line is allocated with malloc(); the caller must
 * eventually call free() to release the storage.
 */
char * readline ( const char *prompt ) {
	char *line;

	readline_history ( prompt, NULL, NULL, &line );
	return line;
}
