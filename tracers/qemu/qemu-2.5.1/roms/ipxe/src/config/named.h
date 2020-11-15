#ifndef CONFIG_NAMED_H
#define CONFIG_NAMED_H

/** @file
 *
 * Named configurations
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/* config/<name>/<header>.h */
#ifdef CONFIG
#define NAMED_CONFIG(_header) <config/CONFIG/_header>
#else
#define NAMED_CONFIG(_header) <config/_header>
#endif

/* config/local/<name>/<header>.h */
#ifdef LOCAL_CONFIG
#define LOCAL_NAMED_CONFIG(_header) <config/local/LOCAL_CONFIG/_header>
#else
#define LOCAL_NAMED_CONFIG(_header) <config/_header>
#endif

#endif /* CONFIG_NAMED_H */
