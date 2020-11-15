#ifndef _IPXE_DOWNLOADER_H
#define _IPXE_DOWNLOADER_H

/** @file
 *
 * Image downloader
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

struct interface;
struct image;

extern int create_downloader ( struct interface *job, struct image *image );

#endif /* _IPXE_DOWNLOADER_H */
