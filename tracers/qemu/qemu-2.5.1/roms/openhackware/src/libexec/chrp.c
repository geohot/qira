/*
 * <chrp.c>
 *
 * Open Hack'Ware BIOS CHRP boot file loader
 * 
 * Copyright (c) 2004-2005 Jocelyn Mayer
 * 
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License V2
 *   as published by the Free Software Foundation
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include "bios.h"
#include "exec.h"
#include "libfs/libfs.h"

/* Simple XML parser */
typedef struct XML_tag_t XML_tag_t;
struct XML_tag_t {
    unsigned char *name;
    XML_tag_t *up;
    int dlen;
    void *data;
};

enum {
    CHRP_TAG_UNKNOWN = 0,
    CHRP_TAG_CHRP_BOOT,
    CHRP_TAG_COMPATIBLE,
    CHRP_TAG_DESCRIPTION,
    CHRP_TAG_BOOT_SCRIPT,
    CHRP_TAG_OS_BADGE_ICONS,
    CHRP_TAG_ICON,
    CHRP_TAG_BITMAP,
    CHRP_TAG_LICENSE,
};

enum {
    CHRP_SCRIPT_IGNORE = 0,
    CHRP_SCRIPT_LOAD_BOOT,
    CHRP_SCRIPT_EMBEDDED,
};

enum {
    XML_STATE_OUT = 0,
    XML_STATE_TAG,
    XML_STATE_DATA,
};

static int XML_get_type (const unsigned char *name)
{
    int ret;

    if (strcmp(name, "CHRP-BOOT") == 0)
        ret = CHRP_TAG_CHRP_BOOT;
    else if (strcmp(name, "COMPATIBLE") == 0)
        ret = CHRP_TAG_COMPATIBLE;
    else if (strcmp(name, "DESCRIPTION") == 0)
        ret = CHRP_TAG_DESCRIPTION;
    else if (strcmp(name, "BOOT-SCRIPT") == 0)
        ret = CHRP_TAG_BOOT_SCRIPT;
    else if (strcmp(name, "OS-BADGE-ICONS") == 0)
        ret = CHRP_TAG_OS_BADGE_ICONS;
    else if (strcmp(name, "ICON") == 0)
        ret = CHRP_TAG_ICON;
    else if (strcmp(name, "BITMAP") == 0)
        ret = CHRP_TAG_BITMAP;
    else if (strcmp(name, "LICENSE") == 0)
        ret = CHRP_TAG_LICENSE;
    else
        ret = CHRP_TAG_UNKNOWN;

    return ret;
}

static unsigned char *strfind (const unsigned char *buf, const unsigned char *str)
{
    const unsigned char *pos;
    int len = strlen(str);

    //    DPRINTF("Look for '%s' in \n'%s'\n", str, buf);
    for (pos = buf; *pos != '\0'; pos++) {
        if (memcmp(pos, str, len) == 0)
            return (unsigned char *)pos;
    }

    return NULL;
}

int exec_load_chrp (inode_t *file, void **dest, void **entry, void **end,
                    uint32_t loffset)
{
#define TMPNAME_LEN 512
    unsigned char tmpname[TMPNAME_LEN], *tmpp, *buf, *pos, *endc, c;
    XML_tag_t *tag, *tmp, *first;
    part_t *part;
    inode_t *inode;
    int state;
    int script_type = CHRP_SCRIPT_IGNORE;
    uint32_t crc, offset = 0;
    int ret, rel = 0;

    buf = malloc(16384);
    /* Check the file head */
    file_seek(file, loffset);
    fs_read(file, buf, 11);
    if (memcmp(buf, "<CHRP-BOOT>", 11) != 0) {
        ERROR("Not an Apple CHRP boot file !\n");
        return -2;
    }
    /* Re-seek at start of the file and start parsing it */
    file_seek(file, loffset);
    pos = buf;
    tag = NULL;
    first = NULL;
    ret = -1;
    fs_read(file, &c, 1);
    offset++;
    for (state = XML_STATE_TAG; state != XML_STATE_OUT;) {
        /* Get next char */
        fs_read(file, &c, 1);
        offset++;
        if ((state == XML_STATE_TAG && c != '>') ||
            (state == XML_STATE_DATA && c != '<')) {
            *pos++ = c;
            continue;
        }
        *pos++ = '\0';
        switch (state) {
        case XML_STATE_TAG:
            if (*buf == '/') {
                if (tag == NULL || strcmp(buf + 1, tag->name) != 0) {
                    ERROR("XML error: open name: '%s' close name: '%s'\n",
                          buf + 1, tag->name);
                    goto out;
                }
                DPRINTF("Close tag: '%s'\n", tag->name);
                switch (XML_get_type(tag->name)) {
                case CHRP_TAG_CHRP_BOOT:
                    /* Nothing to do */
                    break;
                case CHRP_TAG_COMPATIBLE:
                    /* Won't check... */
                    pos = tag->data;
                    if (*(char *)tag->data == 0x0d) {
                        pos++;
                    }
                    DPRINTF("Compatible: '%s'\n", pos);
                    break;
                case CHRP_TAG_DESCRIPTION:
                    pos = tag->data;
                    if (*(char *)tag->data == 0x0d) {
                        pos++;
                    }
                    DPRINTF("Description: '%s'\n", pos);
                    break;
                case CHRP_TAG_BOOT_SCRIPT:
                    /* Here is the interresting part... */
                    crc = crc32(0, tag->data, tag->dlen);
#if 0
                    DPRINTF("Forth script: %08x\n%s\n",
                            crc, (char *)tag->data);
#endif
                    switch (crc) {
                    case 0x5464F92C:
                        /* Mandrake 9.1 CD1 boot script */
                    case 0x4BC74ECF:
                        /* Mandrake 10.1 & 10.2 CD1 boot script */
                    case 0x5B265246:
                        /* Gentoo 1.2-r1 */
                        /* Gentoo 2004.1 minimal install CD */
                        /* Gentoo 1.4 live CDROM */
                        /* Knopix PPC beta-pre12 */
                    case 0x75420D8A:
                        /* Debian woody */
                        /* Debian 3.0r1 */
                        script_type = CHRP_SCRIPT_LOAD_BOOT;
                        goto do_script;
                    case 0x633e4c9c:
                        /* Debian Sarge */
                    case 0xbe3abf60:
                        /* Debian Sarge, installed on a hard disk drive */
                        script_type = CHRP_SCRIPT_LOAD_BOOT;
                        goto do_script;
                    case 0x07b86bfe:
                        /* Linux Fedora Core 3 */
                        script_type = CHRP_SCRIPT_LOAD_BOOT;
                        goto do_script;
                    case 0x9ccdf371:
                        script_type = CHRP_SCRIPT_LOAD_BOOT;
                        goto do_script;
                    case 0xEF423926:
                        /* OpenBSD 3.4 */
                    case 0x68e4f265:
                        /* OpenBSD 3.5 */
                    case 0x3b7ea9e1:
                        /* OpenBSD 3.6 */
                        script_type = CHRP_SCRIPT_LOAD_BOOT;
                        goto do_script;
                    case 0xB7981DBC:
                        /* iBook 2 hw test CDROM */
#if 1
                        script_type = CHRP_SCRIPT_LOAD_BOOT;
                        goto do_script;
#endif
                        
                    case 0xEA06C1A7:
                        /* MacOS 9.2 boot script:
                         * the XCOFF loader is embedded in the file...
                         */
                    case 0x53A95958:
                        /* iBook 2 restore CD (MacOS X 10.2) */
                        script_type = CHRP_SCRIPT_EMBEDDED;
                        pos = strfind(tag->data, "elf-offset");
                        if (pos != NULL) {
                            /* Go backward until we get the value */
                            for (--pos; *pos < '0' || *pos > '9'; pos--)
                                continue;
                            for (; *pos >= '0' && *pos <= '9'; pos--)
                                continue;
                            offset = strtol(pos, NULL, 16);
                            goto do_script;
                        }
                        ERROR("Didn't find boot file offset\n");
                        goto out;
                    case 0x8d5acb86:
                        /* Darwin-7.01
                         * The executable file is embedded after the script
                         */
                        script_type = CHRP_SCRIPT_EMBEDDED;
                        DPRINTF("Boot file embedded at the end of boot script\n");
                        break;
                    default:
                        ERROR("XML error: unknown Forth script: %08x\n%s\n",
                              crc, (char *)tag->data);
                        goto out;
                    }
                    break;

                do_script:
                    switch (script_type) {
                    case CHRP_SCRIPT_LOAD_BOOT:
                        pos = strfind(tag->data, "boot");
                        if (pos != NULL) {
                            /* Eat everything until file name */
                            for (pos += 4; *pos != ','; pos++)
                                continue;
                            /* Eat ',' */
                            for (++pos; isspace(*pos) || *pos == '"'; pos++)
                                continue;
                            /* Find file name end */
                        redo:
                            for (endc = pos;
                                 *endc != ' ' && *endc != '"' &&
                                 *endc != '\n' && *endc != '\r';
                                 endc++) {
                                if (*endc == '\\')
                                    *endc = '/';
                            }
                            if (memcmp(pos, "ofwboot", 7) == 0) {
                                for (pos = endc + 1; *pos == ' '; pos++)
                                    continue;
                                goto redo;
                            }
                            *endc = '\0';
                        }
                        DPRINTF("Real boot file is: '%s'\n", pos);
                        part = fs_inode_get_part(file);
                        /* check if it's a path or just a file */
                        tmpp = pos;
                        if ((pos[0] == '/' && pos[1] == '/') ||
                            pos[0] != '/') {
                            unsigned char *bootdir;
                            bootdir = fs_get_boot_dirname(part_fs(part));
                            if (bootdir == NULL) {
                                ERROR("Cannot get boot directory name\n");
                                bug();
                            }
                            snprintf(tmpname, TMPNAME_LEN,
                                     "%s/%s", bootdir, pos);
                            tmpname[TMPNAME_LEN - 1] = '\0';
                            rel++;
                            pos = tmpname;
                            DPRINTF("'%s' => '%s'\n", bootdir, pos);
                        }
                    retry:
                        inode = fs_open(part_fs(part), pos);
                        if (inode == NULL) {
                            ERROR("Real boot inode '%s' not found\n", pos);
                            /* Try in root directory */
                            if (rel == 1) {
                                for (; *tmpp == '/'; tmpp++)
                                    continue;
                                snprintf(tmpname, TMPNAME_LEN, "/%s", tmpp);
                                tmpname[TMPNAME_LEN - 1] = '\0';
                                rel++;
                                goto retry;
                            }
                            
                            bug();
                        }
                        ret = _bootfile_load(inode, dest, entry, end, 0, -1);
                        fs_close(inode);
                        goto out;
                    case CHRP_SCRIPT_EMBEDDED:
                        DPRINTF("Exec offset: %d %08x\n", offset, offset);
                        ret = 0;
                        goto out;
                    case CHRP_SCRIPT_IGNORE:
                        break;
                    }
                    break;
                case CHRP_TAG_OS_BADGE_ICONS:
                case CHRP_TAG_ICON:
                    /* Ignore it */
                    break;
                case CHRP_TAG_BITMAP:
                    /* Ignore it */
                    break;
                case CHRP_TAG_LICENSE:
                    /* Ignore it */
                    pos = tag->data;
                    if (*(char *)tag->data == 0x0d) {
                        pos++;
                    }
                    DPRINTF("License: '%s'\n", pos);
                    break;
                default:
                    ERROR("XML error: unknown tag: '%s'\n", tag->name);
                    goto out;
                }
                tmp = tag->up;
                if (tmp == NULL)
                    state = XML_STATE_OUT;
                else
                    state = XML_STATE_DATA;
                free(tag->name);
                free(tag->data);
                free(tag);
                tag = tmp;
            } else {
                tmp = malloc(sizeof(XML_tag_t));
                if (tmp == NULL) {
                    ERROR("Cannot allocate new tag\n");
                    goto out;
                }
                tmp->up = tag;
                /* Ignore tag attributes */
                pos = strchr(buf, ' ');
                if (pos != NULL)
                    *pos = '\0';
                tmp->name = strdup(buf);
                tag = tmp;
                if (first == NULL)
                    first = tag;
                DPRINTF("Open tag '%s'\n", tag->name);
                state = XML_STATE_DATA;
            }
            break;
        case XML_STATE_DATA:
            if (tag->data == NULL) {
                tag->dlen = pos - buf;
                tag->data = malloc(tag->dlen);
                memcpy(tag->data, buf, tag->dlen);
            }
            state = XML_STATE_TAG;
            break;
        }
        pos = buf;
    }
    ret = 0;
    fs_read(file, &c, 1);
    fs_read(file, &c, 1);
    offset += 2;
 out:
#if 1
    for (; tag != NULL; tag = tmp) {
        tmp = tag->up;
        free(tag->name);
        free(tag->data);
        free(tag);
    }
#endif
    if (ret == 0 && script_type == CHRP_SCRIPT_EMBEDDED) {
        DPRINTF("Load embedded file from offset %d (%d => %d)\n",
                offset, loffset, loffset + offset);
        ret = _bootfile_load(file, dest, entry, end, loffset + offset, -1);
    }
    DPRINTF("Done\n");

    return ret;
}
