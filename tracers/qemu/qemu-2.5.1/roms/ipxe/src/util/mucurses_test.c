#include "../include/curses.h"
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

void get_iscsi_chap_secret( char * );
void mdelay( int msecs );

int main ( void ) {
	char secret[16];
	initscr();
	echo();
	werase(stdscr);
	box( stdscr, '|', '-' );
	get_iscsi_chap_secret(secret);

	mvwprintw( stdscr, 3, 5, "password is \"%s\"", secret );
	mdelay(2500);

	stdscr->scr->exit(stdscr->scr);

	return 0;
}

void get_iscsi_chap_secret( char *sec ) {
	char 	*title = "Set new iSCSI CHAP secret",
		*msg = "Configure the iSCSI access secret",
		pw1[17], pw2[17];
	WINDOW *secret;

	secret = newwin( stdscr->height / 2,
			 stdscr->width / 2,
			 stdscr->height / 4,
			 stdscr->width / 4 );

	wborder( secret, '|', '|', '-', '-', '+', '+', '+', '+' );
	mvwprintw( secret, 1, 2, "%s", title );
	mvwhline( secret, 2, 1, '-' | secret->attrs, secret->width - 2 );
	mvwprintw( secret, 4, 2, "%s", msg );
	mvwprintw( secret, 6, 3, "secret" );
	mvwprintw( secret, 8, 3, "confirm" );
 start:
	mvwhline( secret, 6, 12, '_' | secret->attrs, 16 );
	mvwhline( secret, 8, 12, '_' | secret->attrs, 16 );

	wmove( secret, 6, 12 );
	wgetnstr( secret, pw1, 16 );
	wmove( secret, 8, 12 );
	wgetnstr( secret, pw2, 16 );

	if ( strcmp( pw1, pw2 ) == 0 ) {
		strcpy( sec, pw1 );
		werase( secret );
	}
	else {
		mvwprintw( secret, 10, 3, "Passwords do not match" );
		goto start;
	}
}

void mdelay ( int msecs ) {
	usleep( msecs * 1000 );
}
