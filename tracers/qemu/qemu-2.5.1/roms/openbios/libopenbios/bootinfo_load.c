/*
 *
 *       <bootinfo_load.c>
 *
 *       bootinfo file loader
 *
 *   Copyright (C) 2009 Laurent Vivier (Laurent@vivier.eu)
 *
 *   Original XML parser by Blue Swirl <blauwirbel@gmail.com>
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   version 2
 *
 */

#include "config.h"
#include "libopenbios/bindings.h"
#include "libopenbios/bootinfo_load.h"
#include "libopenbios/ofmem.h"
#include "libc/vsprintf.h"

//#define DEBUG_BOOTINFO

#ifdef DEBUG_BOOTINFO
#define DPRINTF(fmt, args...) \
    do { printk("%s: " fmt, __func__ , ##args); } while (0)
#else
#define DPRINTF(fmt, args...) \
    do { } while (0)
#endif

static char *
get_device( const char *path )
{
	int i;
	static char buf[1024];

	for (i = 0; i < sizeof(buf) && path[i] && path[i] != ':'; i++)
		buf[i] = path[i];
	buf[i] = 0;

	return buf;
}

static char *
get_partition( const char *path )
{
	static char buf[2];

	buf[0] = '\0';
	buf[1] = '\0';

	while ( *path && *path != ':' )
		path++;

	if (!*path)
		return buf;
	path++;

	if (path[0] == ',' || !strchr(path, ',')) /* if there is not a ',' or no partition id then return */
		return buf;

	/* Must be a partition id */
	buf[0] = path[0];

	return buf;
}

static char *
get_filename( const char * path , char **dirname)
{
        static char buf[1024];
        char *filename;

        while ( *path && *path != ':' )
                path++;

        if (!*path) {
                *dirname = NULL;
                return NULL;
        }
        path++;

        while ( *path && isdigit(*path) )
                path++;

        if (*path == ',')
                path++;

        strncpy(buf, path, sizeof(buf));
        buf[sizeof(buf) - 1] = 0;

        filename = strrchr(buf, '\\');
        if (filename) {
                *dirname = buf;
                (*filename++) = 0;
        } else {
                *dirname = NULL;
                filename = buf;
        }

        return filename;
}

int
is_bootinfo(char *bootinfo)
{
	return (strncasecmp(bootinfo, "<chrp-boot", 10) ? 0 : -1);
}

int 
bootinfo_load(struct sys_info *info, const char *filename)
{
	// Currently not implemented
	return LOADER_NOT_SUPPORT;
}

/*
  Parse SGML structure like:
  <chrp-boot>
  <description>Debian/GNU Linux Installation on IBM CHRP hardware</description>
  <os-name>Debian/GNU Linux for PowerPC</os-name>
  <boot-script>boot &device;:\install\yaboot</boot-script>
  <icon size=64,64 color-space=3,3,2>

  CHRP system bindings are described at:
  http://playground.sun.com/1275/bindings/chrp/chrp1_7a.ps
*/

void
bootinfo_init_program(void)
{
	char *base;
	int proplen;
	phandle_t chosen;
	int tag, taglen, script, scriptlen, scriptvalid, entity, chrp;
	char tagbuf[128], c;
	char *device, *filename, *directory, *partition;
	int current, size;
	char *bootscript;
        char *tmp;
	char bootpath[1024];

	/* Parse the boot script */

	chosen = find_dev("/chosen");
	tmp = get_property(chosen, "bootpath", &proplen);
	memcpy(bootpath, tmp, proplen);
	bootpath[proplen] = 0;

	DPRINTF("bootpath %s\n", bootpath);

	device = get_device(bootpath);
	partition = get_partition(bootpath);
	filename = get_filename(bootpath, &directory);

	feval("load-base");
	base = (char*)cell2pointer(POP());

	feval("load-size");
	size = POP();

	/* Some bootinfo scripts contain a binary payload after the
	   NULL-terminated Forth string such as OS 9. Restrict our
	   size to just the Forth section, otherwise we end up trying
	   to allocate memory for the entire binary which might fail. */
	size = strnlen(base, size);

	bootscript = malloc(size);
	if (bootscript == NULL) {
		DPRINTF("Can't malloc %d bytes\n", size);
		return;
	}

	if (!is_bootinfo(base)) {
		DPRINTF("Not a valid bootinfo memory image\n");
                free(bootscript);
		return;
	}

	chrp = 0;
	tag = 0;
	taglen = 0;
	script = 0;
	scriptvalid = 0;
	scriptlen = 0;
	entity = 0;
	current = 0;
	while (current < size) {

		c = base[current++];

		if (c == '<') {
			script = 0;
			tag = 1;
			taglen = 0;
		} else if (c == '>') {
			tag = 0;
			tagbuf[taglen] = '\0';
			if (strncasecmp(tagbuf, "chrp-boot", 9) == 0) {
				chrp = 1;
			} else if (chrp == 1) {
				if (strncasecmp(tagbuf, "boot-script", 11) == 0) {
					script = 1;
					scriptlen = 0;
				} else if (strncasecmp(tagbuf, "/boot-script", 12) == 0) {

					script = 0;
					bootscript[scriptlen] = '\0';

					DPRINTF("got bootscript %s\n",
						bootscript);

					scriptvalid = -1;

					break;
				} else if (strncasecmp(tagbuf, "/chrp-boot", 10) == 0)
					break;
			}
		} else if (tag && taglen < sizeof(tagbuf)) {
			tagbuf[taglen++] = c;
		} else if (script && c == '&') {
			entity = 1;
			taglen = 0;
		} else if (entity && c ==';') {
			entity = 0;
			tagbuf[taglen] = '\0';
			if (strncasecmp(tagbuf, "lt", 2) == 0) {
				bootscript[scriptlen++] = '<';
			} else if (strncasecmp(tagbuf, "gt", 2) == 0) {
				bootscript[scriptlen++] = '>';
			} else if (strncasecmp(tagbuf, "device", 6) == 0) {
				strcpy(bootscript + scriptlen, device);
				scriptlen += strlen(device);
			} else if (strncasecmp(tagbuf, "partition", 9) == 0) {
				strcpy(bootscript + scriptlen, partition);
				scriptlen += strlen(partition);
			} else if (strncasecmp(tagbuf, "directory", 9) == 0) {
				strcpy(bootscript + scriptlen, directory);
				scriptlen += strlen(directory);
			} else if (strncasecmp(tagbuf, "filename", 8) == 0) {
				strcpy(bootscript + scriptlen, filename);
				scriptlen += strlen(filename);
			} else if (strncasecmp(tagbuf, "full-path", 9) == 0) {
				strcpy(bootscript + scriptlen, bootpath);
				scriptlen += strlen(bootpath);
			} else { /* unknown, keep it */
				bootscript[scriptlen] = '&';
				strcpy(bootscript + scriptlen + 1, tagbuf);
				scriptlen += taglen + 1;
				bootscript[scriptlen] = ';';
				scriptlen++;
			}
		} else if (entity && taglen < sizeof(tagbuf)) {
			tagbuf[taglen++] = c;
		} else if (script && scriptlen < size) {
			bootscript[scriptlen++] = c;
		}
	}

	/* If the payload is bootinfo then we execute it immediately */
	if (scriptvalid) {
		DPRINTF("bootscript: %s\n", bootscript);
		feval(bootscript);
	}
	else
		DPRINTF("Unable to parse bootinfo bootscript\n");
}
