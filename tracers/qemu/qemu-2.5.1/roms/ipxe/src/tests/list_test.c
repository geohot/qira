/*
 * Copyright (C) 2011 Michael Brown <mbrown@fensystems.co.uk>.
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

/** @file
 *
 * List function tests
 *
 */

/* Forcibly enable assertions for list_check() */
#undef NDEBUG

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <ipxe/list.h>
#include <ipxe/test.h>

/** A list test structure */
struct list_test {
	/** List element */
	struct list_head list;
	/** Label */
	char label;
};

/** List test elements */
static struct list_test list_tests[] = {
	{ .label = '0' },
	{ .label = '1' },
	{ .label = '2' },
	{ .label = '3' },
	{ .label = '4' },
	{ .label = '5' },
	{ .label = '6' },
	{ .label = '7' },
	{ .label = '8' },
	{ .label = '9' },
};

/** Test list */
static LIST_HEAD ( test_list );

/**
 * Check list contents are as expected
 *
 * @v list		Test list
 * @v expected		Expected contents
 * @v ok		List contents are as expected
 */
static int list_check_contents ( struct list_head *list,
				 const char *expected ) {
	struct list_test *entry;
	size_t num_entries = 0;

	/* Determine size of list */
	list_for_each_entry ( entry, list, list )
		num_entries++;

	{
		char found[ num_entries + 1 ];
		char found_rev[ num_entries + 1 ];
		char *tmp;

		/* Build up list content string */
		tmp = found;
		list_for_each_entry ( entry, list, list )
			*(tmp++) = entry->label;
		*tmp = '\0';

		/* Sanity check reversed list */
		tmp = &found_rev[ sizeof ( found_rev ) - 1 ];
		*tmp = '\0';
		list_for_each_entry_reverse ( entry, list, list )
			*(--tmp) = entry->label;
		if ( strcmp ( found, found_rev ) != 0 ) {
			printf ( "FAILURE: list reversal mismatch (forward "
				 "\"%s\", reverse \"%s\")\n",
				 found, found_rev  );
			return 0;
		}

		/* Compare against expected content */
		if ( strcmp ( found, expected ) == 0 ) {
			return 1;
		} else {
			printf ( "FAILURE: expected \"%s\", got \"%s\"\n",
			 expected, found );
			return 0;
		}
	}
}

/**
 * Report list test result
 *
 * @v list		Test list
 * @v expected		Expected contents
 */
#define list_contents_ok( list, expected ) do {			\
	ok ( list_check_contents ( (list), (expected) ) );	\
	} while ( 0 )

/**
 * Report list iteration test result
 *
 * @v macro		Iterator macro
 * @v expected		Expected contents
 * @v pos		Iterator
 * @v ...		Arguments to iterator macro
 */
#define list_iterate_ok( macro, expected, pos, ... ) do {	\
	const char *check = expected;				\
	macro ( pos, __VA_ARGS__ ) {				\
		struct list_test *entry =			\
			list_entry ( pos, struct list_test,	\
				     list );			\
		ok ( entry->label == *(check++) );		\
	}							\
	ok ( *check == '\0' );					\
	} while ( 0 )

/**
 * Report list entry iteration test result
 *
 * @v macro		Iterator macro
 * @v expected		Expected contents
 * @v pos		Iterator
 * @v ...		Arguments to iterator macro
 */
#define list_iterate_entry_ok( macro, expected, pos, ... ) do {	\
	const char *check = expected;				\
	macro ( pos, __VA_ARGS__ ) {				\
		ok ( (pos)->label == *(check++) );		\
	}							\
	ok ( *check == '\0' );					\
	} while ( 0 )

/**
 * Perform list self-test
 *
 */
static void list_test_exec ( void ) {
	struct list_head *list = &test_list;
	struct list_head target_list;
	struct list_head *target = &target_list;
	struct list_head *raw_pos;
	struct list_test *pos;
	struct list_test *tmp;

	/* Test initialiser and list_empty() */
	ok ( list_empty ( list ) );
	list_contents_ok ( list, "" );

	/* Test list_add(), list_add_tail() and list_del() */
	INIT_LIST_HEAD ( list );
	list_contents_ok ( list, "" );
	list_add ( &list_tests[4].list, list ); /* prepend */
	list_contents_ok ( list, "4" );
	list_add ( &list_tests[2].list, list ); /* prepend */
	list_contents_ok ( list, "24" );
	list_add_tail ( &list_tests[7].list, list ); /* append */
	list_contents_ok ( list, "247" );
	list_add ( &list_tests[1].list, &list_tests[4].list ); /* after */
	list_contents_ok ( list, "2417" );
	list_add_tail ( &list_tests[8].list, &list_tests[7].list ); /* before */
	list_contents_ok ( list, "24187" );
	list_del ( &list_tests[4].list ); /* delete middle */
	list_contents_ok ( list, "2187" );
	list_del ( &list_tests[2].list ); /* delete first */
	list_contents_ok ( list, "187" );
	list_del ( &list_tests[7].list ); /* delete last */
	list_contents_ok ( list, "18" );
	list_del ( &list_tests[1].list ); /* delete all */
	list_del ( &list_tests[8].list ); /* delete all */
	list_contents_ok ( list, "" );
	ok ( list_empty ( list ) );

	/* Test list_is_singular() */
	INIT_LIST_HEAD ( list );
	ok ( ! list_is_singular ( list ) );
	list_add ( &list_tests[1].list, list );
	ok ( list_is_singular ( list ) );
	list_add ( &list_tests[3].list, list );
	ok ( ! list_is_singular ( list ) );
	list_del ( &list_tests[1].list );
	ok ( list_is_singular ( list ) );

	/* Test list_is_last() */
	INIT_LIST_HEAD ( list );
	list_add_tail ( &list_tests[6].list, list );
	ok ( list_is_last ( &list_tests[6].list, list ) );
	list_add_tail ( &list_tests[4].list, list );
	ok ( list_is_last ( &list_tests[4].list, list ) );
	ok ( ! list_is_last ( &list_tests[6].list, list ) );

	/* Test list_cut_position() - empty list */
	INIT_LIST_HEAD ( list );
	INIT_LIST_HEAD ( target );
	list_cut_position ( target, list, list );
	list_contents_ok ( list, "" );
	list_contents_ok ( target, "" );

	/* Test list_cut_position() - singular list, move nothing */
	INIT_LIST_HEAD ( list );
	INIT_LIST_HEAD ( target );
	list_add_tail ( &list_tests[4].list, list );
	list_cut_position ( target, list, list );
	list_contents_ok ( list, "4" );
	list_contents_ok ( target, "" );

	/* Test list_cut_position() - singular list, move singular entry */
	INIT_LIST_HEAD ( list );
	INIT_LIST_HEAD ( target );
	list_add_tail ( &list_tests[9].list, list );
	list_cut_position ( target, list, &list_tests[9].list );
	list_contents_ok ( list, "" );
	list_contents_ok ( target, "9" );

	/* Test list_cut_position() - multi-entry list, move nothing */
	INIT_LIST_HEAD ( list );
	list_add_tail ( &list_tests[3].list, list );
	list_add_tail ( &list_tests[2].list, list );
	list_add_tail ( &list_tests[7].list, list );
	INIT_LIST_HEAD ( target );
	list_cut_position ( target, list, list );
	list_contents_ok ( list, "327" );
	list_contents_ok ( target, "" );

	/* Test list_cut_position() - multi-entry list, move some */
	INIT_LIST_HEAD ( list );
	INIT_LIST_HEAD ( target );
	list_add_tail ( &list_tests[8].list, list );
	list_add_tail ( &list_tests[0].list, list );
	list_add_tail ( &list_tests[9].list, list );
	list_add_tail ( &list_tests[3].list, list );
	list_add_tail ( &list_tests[2].list, list );
	list_cut_position ( target, list, &list_tests[0].list );
	list_contents_ok ( list, "932" );
	list_contents_ok ( target, "80" );

	/* Test list_cut_position() - multi-entry list, move everything */
	INIT_LIST_HEAD ( list );
	INIT_LIST_HEAD ( target );
	list_add_tail ( &list_tests[3].list, list );
	list_add_tail ( &list_tests[5].list, list );
	list_add_tail ( &list_tests[4].list, list );
	list_add_tail ( &list_tests[7].list, list );
	list_add_tail ( &list_tests[1].list, list );
	list_cut_position ( target, list, &list_tests[1].list );
	list_contents_ok ( list, "" );
	list_contents_ok ( target, "35471" );

	/* Test list_splice() - empty list */
	INIT_LIST_HEAD ( list );
	INIT_LIST_HEAD ( target );
	list_splice ( list, target );
	list_contents_ok ( list, "" );
	list_contents_ok ( target, "" );

	/* Test list_splice() - both lists empty */
	INIT_LIST_HEAD ( list );
	INIT_LIST_HEAD ( target );
	list_splice ( list, target );
	list_contents_ok ( target, "" );

	/* Test list_splice() - source list empty */
	INIT_LIST_HEAD ( list );
	INIT_LIST_HEAD ( target );
	list_add_tail ( &list_tests[1].list, target );
	list_add_tail ( &list_tests[3].list, target );
	list_splice ( list, &list_tests[1].list );
	list_contents_ok ( target, "13" );

	/* Test list_splice() - destination list empty */
	INIT_LIST_HEAD ( list );
	INIT_LIST_HEAD ( target );
	list_add_tail ( &list_tests[6].list, list );
	list_add_tail ( &list_tests[5].list, list );
	list_add_tail ( &list_tests[2].list, list );
	list_splice ( list, target );
	list_contents_ok ( target, "652" );

	/* Test list_splice() - both lists non-empty */
	INIT_LIST_HEAD ( list );
	INIT_LIST_HEAD ( target );
	list_add_tail ( &list_tests[8].list, list );
	list_add_tail ( &list_tests[4].list, list );
	list_add_tail ( &list_tests[5].list, list );
	list_add_tail ( &list_tests[1].list, target );
	list_add_tail ( &list_tests[9].list, target );
	list_splice ( list, &list_tests[1].list );
	list_contents_ok ( target, "18459" );

	/* Test list_splice_tail() - both lists empty */
	INIT_LIST_HEAD ( list );
	INIT_LIST_HEAD ( target );
	list_splice_tail ( list, target );
	list_contents_ok ( target, "" );

	/* Test list_splice_tail() - source list empty */
	INIT_LIST_HEAD ( list );
	INIT_LIST_HEAD ( target );
	list_add_tail ( &list_tests[5].list, target );
	list_splice_tail ( list, &list_tests[5].list );
	list_contents_ok ( target, "5" );

	/* Test list_splice_tail() - destination list empty */
	INIT_LIST_HEAD ( list );
	INIT_LIST_HEAD ( target );
	list_add_tail ( &list_tests[2].list, list );
	list_add_tail ( &list_tests[1].list, list );
	list_add_tail ( &list_tests[0].list, list );
	list_splice_tail ( list, target );
	list_contents_ok ( target, "210" );

	/* Test list_splice_tail() - both lists non-empty */
	INIT_LIST_HEAD ( list );
	INIT_LIST_HEAD ( target );
	list_add_tail ( &list_tests[9].list, list );
	list_add_tail ( &list_tests[5].list, list );
	list_add_tail ( &list_tests[7].list, list );
	list_add_tail ( &list_tests[2].list, target );
	list_add_tail ( &list_tests[4].list, target );
	list_splice_tail ( list, &list_tests[2].list );
	list_contents_ok ( target, "95724" );

	/* Test list_splice_init() */
	INIT_LIST_HEAD ( list );
	INIT_LIST_HEAD ( target );
	list_add_tail ( &list_tests[4].list, list );
	list_add_tail ( &list_tests[1].list, target );
	list_splice_init ( list, target );
	ok ( list_empty ( list ) );
	list_contents_ok ( list, "" );
	list_contents_ok ( target, "41" );

	/* Test list_splice_tail_init() */
	INIT_LIST_HEAD ( list );
	INIT_LIST_HEAD ( target );
	list_add_tail ( &list_tests[3].list, list );
	list_add_tail ( &list_tests[2].list, list );
	list_add_tail ( &list_tests[5].list, target );
	list_splice_tail_init ( list, &list_tests[5].list );
	ok ( list_empty ( list ) );
	list_contents_ok ( list, "" );
	list_contents_ok ( target, "325" );

	/* Test list_entry() */
	INIT_LIST_HEAD ( &list_tests[3].list );  // for list_check()
	ok ( list_entry ( &list_tests[3].list, struct list_test, list )
	     == &list_tests[3] );

	/* Test list_first_entry() and list_last_entry() */
	INIT_LIST_HEAD ( list );
	list_add_tail ( &list_tests[9].list, list );
	list_add_tail ( &list_tests[5].list, list );
	list_add_tail ( &list_tests[6].list, list );
	ok ( list_first_entry ( list, struct list_test, list )
	     == &list_tests[9] );
	ok ( list_last_entry ( list, struct list_test, list )
	     == &list_tests[6] );
	list_del ( &list_tests[9].list );
	ok ( list_first_entry ( list, struct list_test, list )
	     == &list_tests[5] );
	ok ( list_last_entry ( list, struct list_test, list )
	     == &list_tests[6] );
	list_del ( &list_tests[6].list );
	ok ( list_first_entry ( list, struct list_test, list )
	     == &list_tests[5] );
	ok ( list_last_entry ( list, struct list_test, list )
	     == &list_tests[5] );
	list_del ( &list_tests[5].list );
	ok ( list_first_entry ( list, struct list_test, list ) == NULL );
	ok ( list_last_entry ( list, struct list_test, list ) == NULL );

	/* Test list_for_each() */
	INIT_LIST_HEAD ( list );
	list_add_tail ( &list_tests[6].list, list );
	list_add_tail ( &list_tests[7].list, list );
	list_add_tail ( &list_tests[3].list, list );
	list_iterate_ok ( list_for_each, "673", raw_pos, list );

	/* Test list_for_each_entry() and list_for_each_entry_reverse() */
	INIT_LIST_HEAD ( list );
	list_add_tail ( &list_tests[3].list, list );
	list_add_tail ( &list_tests[2].list, list );
	list_add_tail ( &list_tests[6].list, list );
	list_add_tail ( &list_tests[9].list, list );
	list_iterate_entry_ok ( list_for_each_entry, "3269",
				pos, list, list );
	list_iterate_entry_ok ( list_for_each_entry_reverse, "9623",
				pos, list, list );

	/* Test list_for_each_entry_safe() */
	INIT_LIST_HEAD ( list );
	list_add_tail ( &list_tests[2].list, list );
	list_add_tail ( &list_tests[4].list, list );
	list_add_tail ( &list_tests[1].list, list );
	{
		char *expected = "241";
		list_for_each_entry_safe ( pos, tmp, list, list ) {
			list_contents_ok ( list, expected );
			list_del ( &pos->list );
			expected++;
			list_contents_ok ( list, expected );
		}
	}
	ok ( list_empty ( list ) );

	/* Test list_for_each_entry_continue() and
	 * list_for_each_entry_continue_reverse()
	 */
	INIT_LIST_HEAD ( list );
	list_add_tail ( &list_tests[4].list, list );
	list_add_tail ( &list_tests[7].list, list );
	list_add_tail ( &list_tests[2].list, list );
	list_add_tail ( &list_tests[9].list, list );
	list_add_tail ( &list_tests[3].list, list );
	pos = &list_tests[7];
	list_iterate_entry_ok ( list_for_each_entry_continue, "293",
				pos, list, list );
	ok ( pos == list_entry ( list, struct list_test, list ) );
	list_iterate_entry_ok ( list_for_each_entry_continue, "47293",
				pos, list, list );
	pos = &list_tests[3];
	list_iterate_entry_ok ( list_for_each_entry_continue, "",
				pos, list, list );
	pos = &list_tests[2];
	list_iterate_entry_ok ( list_for_each_entry_continue_reverse, "74",
				pos, list, list );
	ok ( pos == list_entry ( list, struct list_test, list ) );
	list_iterate_entry_ok ( list_for_each_entry_continue_reverse, "39274",
				pos, list, list );
	pos = &list_tests[4];
	list_iterate_entry_ok ( list_for_each_entry_continue_reverse, "",
				pos, list, list );

	/* Test list_contains() and list_contains_entry() */
	INIT_LIST_HEAD ( list );
	INIT_LIST_HEAD ( &list_tests[3].list );
	list_add ( &list_tests[8].list, list );
	list_add ( &list_tests[5].list, list );
	ok ( list_contains ( &list_tests[8].list, list ) );
	ok ( list_contains_entry ( &list_tests[8], list, list ) );
	ok ( list_contains ( &list_tests[5].list, list ) );
	ok ( list_contains_entry ( &list_tests[5], list, list ) );
	ok ( ! list_contains ( &list_tests[3].list, list ) );
	ok ( ! list_contains_entry ( &list_tests[3], list, list ) );

	/* Test list_check_contains_entry() */
	INIT_LIST_HEAD ( list );
	list_add ( &list_tests[4].list, list );
	list_add ( &list_tests[0].list, list );
	list_add ( &list_tests[3].list, list );
	list_check_contains_entry ( &list_tests[4], list, list );
	list_check_contains_entry ( &list_tests[0], list, list );
	list_check_contains_entry ( &list_tests[3], list, list );
}

/** List self-test */
struct self_test list_test __self_test = {
	.name = "list",
	.exec = list_test_exec,
};
