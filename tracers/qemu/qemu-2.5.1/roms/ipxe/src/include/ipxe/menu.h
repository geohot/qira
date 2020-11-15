#ifndef _IPXE_MENU_H
#define _IPXE_MENU_H

/** @file
 *
 * Menu selection
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/list.h>

/** A menu */
struct menu {
	/** List of menus */
	struct list_head list;
	/** Name */
	const char *name;
	/** Title */
	const char *title;
	/** Menu items */
	struct list_head items;
};

/** A menu item */
struct menu_item {
	/** List of menu items */
	struct list_head list;
	/** Label */
	const char *label;
	/** Text */
	const char *text;
	/** Shortcut key */
	int shortcut;
	/** Is default item */
	int is_default;
};

extern struct menu * create_menu ( const char *name, const char *title );
extern struct menu_item * add_menu_item ( struct menu *menu, const char *label,
					  const char *text, int shortcut,
					  int is_default );
extern void destroy_menu ( struct menu *menu );
extern struct menu * find_menu ( const char *name );
extern int show_menu ( struct menu *menu, unsigned long timeout,
		       const char *select, struct menu_item **selected );

#endif /* _IPXE_MENU_H */
