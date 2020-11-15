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
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <curses.h>
#include <ipxe/console.h>
#include <ipxe/settings.h>
#include <ipxe/editbox.h>
#include <ipxe/keys.h>
#include <ipxe/ansicol.h>
#include <ipxe/jumpscroll.h>
#include <ipxe/settings_ui.h>
#include <config/branding.h>

/** @file
 *
 * Option configuration console
 *
 */

/* Screen layout */
#define TITLE_ROW		1U
#define SETTINGS_LIST_ROW	3U
#define SETTINGS_LIST_COL	1U
#define SETTINGS_LIST_ROWS	( LINES - 6U - SETTINGS_LIST_ROW )
#define INFO_ROW		( LINES - 5U )
#define ALERT_ROW		( LINES - 2U )
#define INSTRUCTION_ROW		( LINES - 2U )
#define INSTRUCTION_PAD "     "

/** Layout of text within a setting row */
#define SETTING_ROW_TEXT( cols ) struct {				\
	char start[0];							\
	char pad1[1];							\
	union {								\
		char settings[ cols - 1 - 1 - 1 - 1 ];			\
		struct {						\
			char name[15];					\
			char pad2[1];					\
			char value[ cols - 1 - 15 - 1 - 1 - 1 - 1 ];	\
		} setting;						\
	} u;								\
	char pad3[1];							\
	char nul;							\
} __attribute__ (( packed ))

/** A settings user interface row */
struct settings_ui_row {
	/** Target configuration settings block
	 *
	 * Valid only for rows that lead to new settings blocks.
	 */
	struct settings *settings;
	/** Configuration setting origin
	 *
	 * Valid only for rows that represent individual settings.
	 */
	struct settings *origin;
	/** Configuration setting
	 *
	 * Valid only for rows that represent individual settings.
	 */
	struct setting setting;
	/** Screen row */
	unsigned int row;
	/** Edit box widget used for editing setting */
	struct edit_box editbox;
	/** Editing in progress flag */
	int editing;
	/** Buffer for setting's value */
	char value[256]; /* enough size for a DHCP string */
};

/** A settings user interface */
struct settings_ui {
	/** Settings block */
	struct settings *settings;
	/** Jump scroller */
	struct jump_scroller scroll;
	/** Current row */
	struct settings_ui_row row;
};

/**
 * Select a setting
 *
 * @v ui		Settings user interface
 * @v index		Index of setting row
 * @ret count		Number of setting rows
 */
static unsigned int select_setting_row ( struct settings_ui *ui,
					 unsigned int index ) {
	SETTING_ROW_TEXT ( COLS ) *text;
	struct settings *settings;
	struct setting *setting;
	struct setting *previous = NULL;
	unsigned int count = 0;

	/* Initialise structure */
	memset ( &ui->row, 0, sizeof ( ui->row ) );
	ui->row.row = ( SETTINGS_LIST_ROW + index - ui->scroll.first );

	/* Include parent settings block, if applicable */
	if ( ui->settings->parent && ( count++ == index ) ) {
		ui->row.settings = ui->settings->parent;
		snprintf ( ui->row.value, sizeof ( ui->row.value ),
			   "../" );
	}

	/* Include any child settings blocks, if applicable */
	list_for_each_entry ( settings, &ui->settings->children, siblings ) {
		if ( count++ == index ) {
			ui->row.settings = settings;
			snprintf ( ui->row.value, sizeof ( ui->row.value ),
				   "%s/", settings->name );
		}
	}

	/* Include any applicable settings */
	for_each_table_entry ( setting, SETTINGS ) {

		/* Skip inapplicable settings */
		if ( ! setting_applies ( ui->settings, setting ) )
			continue;

		/* Skip duplicate settings */
		if ( previous && ( setting_cmp ( setting, previous ) == 0 ) )
			continue;
		previous = setting;

		/* Read current setting value and origin */
		if ( count++ == index ) {
			fetchf_setting ( ui->settings, setting, &ui->row.origin,
					 &ui->row.setting, ui->row.value,
					 sizeof ( ui->row.value ) );
		}
	}

	/* Initialise edit box */
	init_editbox ( &ui->row.editbox, ui->row.value,
		       sizeof ( ui->row.value ), NULL, ui->row.row,
		       ( SETTINGS_LIST_COL +
			 offsetof ( typeof ( *text ), u.setting.value ) ),
		       sizeof ( text->u.setting.value ), 0 );

	return count;
}

/**
 * Copy string without NUL termination
 *
 * @v dest		Destination
 * @v src		Source
 * @v len		Maximum length of destination
 * @ret len		Length of (unterminated) string
 */
static size_t string_copy ( char *dest, const char *src, size_t len ) {
	size_t src_len;

	src_len = strlen ( src );
	if ( len > src_len )
		len = src_len;
	memcpy ( dest, src, len );
	return len;
}

/**
 * Draw setting row
 *
 * @v ui		Settings UI
 */
static void draw_setting_row ( struct settings_ui *ui ) {
	SETTING_ROW_TEXT ( COLS ) text;
	unsigned int curs_offset;
	char *value;

	/* Fill row with spaces */
	memset ( &text, ' ', sizeof ( text ) );
	text.nul = '\0';

	/* Construct row content */
	if ( ui->row.settings ) {

		/* Construct space-padded name */
		curs_offset = ( offsetof ( typeof ( text ), u.settings ) +
				string_copy ( text.u.settings,
					      ui->row.value,
					      sizeof ( text.u.settings ) ) );

	} else {

		/* Construct dot-padded name */
		memset ( text.u.setting.name, '.',
			 sizeof ( text.u.setting.name ) );
		string_copy ( text.u.setting.name, ui->row.setting.name,
			      sizeof ( text.u.setting.name ) );

		/* Construct space-padded value */
		value = ui->row.value;
		if ( ! *value )
			value = "<not specified>";
		curs_offset = ( offsetof ( typeof ( text ), u.setting.value ) +
				string_copy ( text.u.setting.value, value,
					      sizeof ( text.u.setting.value )));
	}

	/* Print row */
	if ( ( ui->row.origin == ui->settings ) || ( ui->row.settings != NULL ))
		attron ( A_BOLD );
	mvprintw ( ui->row.row, SETTINGS_LIST_COL, "%s", text.start );
	attroff ( A_BOLD );
	move ( ui->row.row, ( SETTINGS_LIST_COL + curs_offset ) );
}

/**
 * Edit setting ui
 *
 * @v ui		Settings UI
 * @v key		Key pressed by user
 * @ret key		Key returned to application, or zero
 */
static int edit_setting ( struct settings_ui *ui, int key ) {
	assert ( ui->row.setting.name != NULL );
	ui->row.editing = 1;
	return edit_editbox ( &ui->row.editbox, key );
}

/**
 * Save setting ui value back to configuration settings
 *
 * @v ui		Settings UI
 */
static int save_setting ( struct settings_ui *ui ) {
	assert ( ui->row.setting.name != NULL );
	return storef_setting ( ui->settings, &ui->row.setting, ui->row.value );
}

/**
 * Print message centred on specified row
 *
 * @v row		Row
 * @v fmt		printf() format string
 * @v args		printf() argument list
 */
static void vmsg ( unsigned int row, const char *fmt, va_list args ) {
	char buf[COLS];
	size_t len;

	len = vsnprintf ( buf, sizeof ( buf ), fmt, args );
	mvprintw ( row, ( ( COLS - len ) / 2 ), "%s", buf );
}

/**
 * Print message centred on specified row
 *
 * @v row		Row
 * @v fmt		printf() format string
 * @v ..		printf() arguments
 */
static void msg ( unsigned int row, const char *fmt, ... ) {
	va_list args;

	va_start ( args, fmt );
	vmsg ( row, fmt, args );
	va_end ( args );
}

/**
 * Clear message on specified row
 *
 * @v row		Row
 */
static void clearmsg ( unsigned int row ) {
	move ( row, 0 );
	clrtoeol();
}

/**
 * Print alert message
 *
 * @v fmt		printf() format string
 * @v args		printf() argument list
 */
static void valert ( const char *fmt, va_list args ) {
	clearmsg ( ALERT_ROW );
	color_set ( CPAIR_ALERT, NULL );
	vmsg ( ALERT_ROW, fmt, args );
	sleep ( 2 );
	color_set ( CPAIR_NORMAL, NULL );
	clearmsg ( ALERT_ROW );
}

/**
 * Print alert message
 *
 * @v fmt		printf() format string
 * @v ...		printf() arguments
 */
static void alert ( const char *fmt, ... ) {
	va_list args;

	va_start ( args, fmt );
	valert ( fmt, args );
	va_end ( args );
}

/**
 * Draw title row
 *
 * @v ui		Settings UI
 */
static void draw_title_row ( struct settings_ui *ui ) {
	const char *name;

	clearmsg ( TITLE_ROW );
	name = settings_name ( ui->settings );
	attron ( A_BOLD );
	msg ( TITLE_ROW, PRODUCT_SHORT_NAME " configuration settings%s%s",
	      ( name[0] ? " - " : "" ), name );
	attroff ( A_BOLD );
}

/**
 * Draw information row
 *
 * @v ui		Settings UI
 */
static void draw_info_row ( struct settings_ui *ui ) {
	char buf[32];

	/* Draw nothing unless this row represents a setting */
	clearmsg ( INFO_ROW );
	clearmsg ( INFO_ROW + 1 );
	if ( ! ui->row.setting.name )
		return;

	/* Determine a suitable setting name */
	setting_name ( ( ui->row.origin ?
			 ui->row.origin : ui->settings ),
		       &ui->row.setting, buf, sizeof ( buf ) );

	/* Draw row */
	attron ( A_BOLD );
	msg ( INFO_ROW, "%s - %s", buf, ui->row.setting.description );
	attroff ( A_BOLD );
	color_set ( CPAIR_URL, NULL );
	msg ( ( INFO_ROW + 1 ), PRODUCT_SETTING_URI, ui->row.setting.name );
	color_set ( CPAIR_NORMAL, NULL );
}

/**
 * Draw instruction row
 *
 * @v ui		Settings UI
 */
static void draw_instruction_row ( struct settings_ui *ui ) {

	clearmsg ( INSTRUCTION_ROW );
	if ( ui->row.editing ) {
		msg ( INSTRUCTION_ROW,
		      "Enter - accept changes" INSTRUCTION_PAD
		      "Ctrl-C - discard changes" );
	} else {
		msg ( INSTRUCTION_ROW,
		      "%sCtrl-X - exit configuration utility",
		      ( ( ui->row.origin == ui->settings ) ?
			"Ctrl-D - delete setting" INSTRUCTION_PAD : "" ) );
	}
}

/**
 * Draw the current block of setting rows
 *
 * @v ui		Settings UI
 */
static void draw_setting_rows ( struct settings_ui *ui ) {
	unsigned int i;

	/* Draw ellipses before and/or after the list as necessary */
	color_set ( CPAIR_SEPARATOR, NULL );
	mvaddstr ( ( SETTINGS_LIST_ROW - 1 ), ( SETTINGS_LIST_COL + 1 ),
		   jump_scroll_is_first ( &ui->scroll ) ? "   " : "..." );
	mvaddstr ( ( SETTINGS_LIST_ROW + SETTINGS_LIST_ROWS ),
		   ( SETTINGS_LIST_COL + 1 ),
		   jump_scroll_is_last ( &ui->scroll ) ? "   " : "..." );
	color_set ( CPAIR_NORMAL, NULL );

	/* Draw visible settings. */
	for ( i = 0 ; i < SETTINGS_LIST_ROWS ; i++ ) {
		if ( ( ui->scroll.first + i ) < ui->scroll.count ) {
			select_setting_row ( ui, ( ui->scroll.first + i ) );
			draw_setting_row ( ui );
		} else {
			clearmsg ( SETTINGS_LIST_ROW + i );
		}
	}
}

/**
 * Select settings block
 *
 * @v ui		Settings UI
 * @v settings		Settings block
 */
static void select_settings ( struct settings_ui *ui,
			      struct settings *settings ) {

	ui->settings = settings_target ( settings );
	ui->scroll.count = select_setting_row ( ui, 0 );
	ui->scroll.rows = SETTINGS_LIST_ROWS;
	ui->scroll.current = 0;
	ui->scroll.first = 0;
	draw_title_row ( ui );
	draw_setting_rows ( ui );
	select_setting_row ( ui, 0 );
}

static int main_loop ( struct settings *settings ) {
	struct settings_ui ui;
	unsigned int previous;
	int redraw = 1;
	int move;
	int key;
	int rc;

	/* Print initial screen content */
	color_set ( CPAIR_NORMAL, NULL );
	memset ( &ui, 0, sizeof ( ui ) );
	select_settings ( &ui, settings );

	while ( 1 ) {

		/* Redraw rows if necessary */
		if ( redraw ) {
			draw_info_row ( &ui );
			draw_instruction_row ( &ui );
			color_set ( ( ui.row.editing ?
				      CPAIR_EDIT : CPAIR_SELECT ), NULL );
			draw_setting_row ( &ui );
			color_set ( CPAIR_NORMAL, NULL );
			curs_set ( ui.row.editing );
			redraw = 0;
		}

		/* Edit setting, if we are currently editing */
		if ( ui.row.editing ) {

			/* Sanity check */
			assert ( ui.row.setting.name != NULL );

			/* Redraw edit box */
			color_set ( CPAIR_EDIT, NULL );
			draw_editbox ( &ui.row.editbox );
			color_set ( CPAIR_NORMAL, NULL );

			/* Process keypress */
			key = edit_setting ( &ui, getkey ( 0 ) );
			switch ( key ) {
			case CR:
			case LF:
				if ( ( rc = save_setting ( &ui ) ) != 0 )
					alert ( " %s ", strerror ( rc ) );
				/* Fall through */
			case CTRL_C:
				select_setting_row ( &ui, ui.scroll.current );
				redraw = 1;
				break;
			default:
				/* Do nothing */
				break;
			}

			continue;
		}

		/* Otherwise, navigate through settings */
		key = getkey ( 0 );
		move = jump_scroll_key ( &ui.scroll, key );
		if ( move ) {
			previous = ui.scroll.current;
			jump_scroll_move ( &ui.scroll, move );
			if ( ui.scroll.current != previous ) {
				draw_setting_row ( &ui );
				redraw = 1;
				if ( jump_scroll ( &ui.scroll ) )
					draw_setting_rows ( &ui );
				select_setting_row ( &ui, ui.scroll.current );
			}
			continue;
		}

		/* Handle non-navigation keys */
		switch ( key ) {
		case CTRL_D:
			if ( ! ui.row.setting.name )
				break;
			if ( ( rc = delete_setting ( ui.settings,
						     &ui.row.setting ) ) != 0 ){
				alert ( " %s ", strerror ( rc ) );
			}
			select_setting_row ( &ui, ui.scroll.current );
			redraw = 1;
			break;
		case CTRL_X:
			return 0;
		case CR:
		case LF:
			if ( ui.row.settings ) {
				select_settings ( &ui, ui.row.settings );
				redraw = 1;
			}
			/* Fall through */
		default:
			if ( ui.row.setting.name ) {
				edit_setting ( &ui, key );
				redraw = 1;
			}
			break;
		}
	}
}

int settings_ui ( struct settings *settings ) {
	int rc;

	initscr();
	start_color();
	color_set ( CPAIR_NORMAL, NULL );
	curs_set ( 0 );
	erase();
	
	rc = main_loop ( settings );

	endwin();

	return rc;
}
