/*
 * <xcoff.c>
 *
 * Open Hack'Ware BIOS XCOFF executable file loader
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
#include "bios.h"
#include "exec.h"

uint32_t fs_inode_get_size (inode_t *inode);

/* XCOFF executable loader */
typedef struct COFF_filehdr_t {
    uint16_t f_magic;	/* magic number			*/
    uint16_t f_nscns;	/* number of sections		*/
    uint32_t f_timdat;	/* time & date stamp		*/
    uint32_t f_symptr;	/* file pointer to symtab	*/
    uint32_t f_nsyms;	/* number of symtab entries	*/
    uint16_t f_opthdr;	/* sizeof(optional hdr)		*/
    uint16_t f_flags;	/* flags			*/
} COFF_filehdr_t;

/* IBM RS/6000 */
#define U802WRMAGIC     0730    /* writeable text segments **chh**      */
#define U802ROMAGIC     0735    /* readonly sharable text segments      */
#define U802TOCMAGIC    0737    /* readonly text segments and TOC       */

/*
 *   Bits for f_flags:
 *
 *	F_RELFLG	relocation info stripped from file
 *	F_EXEC		file is executable  (i.e. no unresolved external
 *			references)
 *	F_LNNO		line numbers stripped from file
 *	F_LSYMS		local symbols stripped from file
 *	F_MINMAL	this is a minimal object file (".m") output of fextract
 *	F_UPDATE	this is a fully bound update file, output of ogen
 *	F_SWABD		this file has had its bytes swabbed (in names)
 *	F_AR16WR	this file has the byte ordering of an AR16WR
 *			(e.g. 11/70) machine
 *	F_AR32WR	this file has the byte ordering of an AR32WR machine
 *			(e.g. vax and iNTEL 386)
 *	F_AR32W		this file has the byte ordering of an AR32W machine
 *			(e.g. 3b,maxi)
 *	F_PATCH		file contains "patch" list in optional header
 *	F_NODF		(minimal file only) no decision functions for
 *			replaced functions
 */

#define  COFF_F_RELFLG		0000001
#define  COFF_F_EXEC		0000002
#define  COFF_F_LNNO		0000004
#define  COFF_F_LSYMS		0000010
#define  COFF_F_MINMAL		0000020
#define  COFF_F_UPDATE		0000040
#define  COFF_F_SWABD		0000100
#define  COFF_F_AR16WR		0000200
#define  COFF_F_AR32WR		0000400
#define  COFF_F_AR32W		0001000
#define  COFF_F_PATCH		0002000
#define  COFF_F_NODF		0002000

typedef struct COFF_aouthdr_t {
    uint16_t magic;      /* type of file			  */
    uint16_t vstamp;     /* version stamp		          */
    uint32_t tsize;      /* text size in bytes, padded to FW bdry */
    uint32_t dsize;      /* initialized data "  "	          */
    uint32_t bsize;      /* uninitialized data "   "	          */
    uint32_t entry;	 /* entry pt.			          */
    uint32_t text_start; /* base of text used for this file       */
    uint32_t data_start; /* base of data used for this file       */
    uint32_t o_toc;	 /* address of TOC                        */
    uint16_t o_snentry;	 /* section number of entry point         */
    uint16_t o_sntext;	 /* section number of .text section       */
    uint16_t o_sndata;	 /* section number of .data section       */
    uint16_t o_sntoc;	 /* section number of TOC                 */
    uint16_t o_snloader; /* section number of .loader section     */
    uint16_t o_snbss;	 /* section number of .bss section        */
    uint16_t o_algntext; /* .text alignment                       */
    uint16_t o_algndata; /* .data alignment                       */
    uint16_t o_modtype;	 /* module type (??)                      */
    uint16_t o_cputype;	 /* cpu type                              */
    uint32_t o_maxstack; /* max stack size (??)                   */
    uint32_t o_maxdata;	 /* max data size (??)                    */
    char o_resv2[12];	 /* reserved                              */
} COFF_aouthdr_t;

#define AOUT_MAGIC	0x010b

typedef struct COFF_scnhdr_t {
    char s_name[8];	/* section name			    */
    uint32_t s_paddr;	/* physical address, aliased s_nlib */
    uint32_t s_vaddr;	/* virtual address		    */
    uint32_t s_size;	/* section size			    */
    uint32_t s_scnptr;	/* file ptr to raw data for section */
    uint32_t s_relptr;	/* file ptr to relocation	    */
    uint32_t s_lnnoptr;	/* file ptr to line numbers	    */
    uint16_t s_nreloc;	/* number of relocation entries	    */
    uint16_t s_nlnno;	/* number of line number entries    */
    uint32_t s_flags;	/* flags			    */
} COFF_scnhdr_t;

int exec_load_xcoff (inode_t *file, void **dest, void **entry, void **end,
                     uint32_t loffset)
{
    COFF_filehdr_t fhdr;
    COFF_aouthdr_t ahdr;
    COFF_scnhdr_t shdr;
    void *first, *last;
    uint32_t offset;
    int i;

    file_seek(file, loffset);
    if (fs_read(file, &fhdr, sizeof(COFF_filehdr_t)) < 0) {
        ERROR("Cannot load first bloc of file...\n");
        return -1;
    }
    if (fhdr.f_magic != U802WRMAGIC && fhdr.f_magic != U802ROMAGIC &&
        fhdr.f_magic != U802TOCMAGIC && fhdr.f_magic != 0x01DF) {
        DPRINTF("Not a XCOFF file %02x %08x\n", fhdr.f_magic,
                *(uint32_t *)&fhdr.f_magic);
        return -2;
    }
    if (fhdr.f_magic != 0x01DF && (fhdr.f_flags & COFF_F_EXEC) == 0) {
        ERROR("Not an executable XCOFF file %02x\n", fhdr.f_flags);
        return -2;
    }
    if (fhdr.f_opthdr != sizeof(COFF_aouthdr_t)) {
        ERROR("AOUT optional error size missmactch in XCOFF file\n");
        return -2;
    }
    if (fs_read(file, &ahdr, sizeof(COFF_aouthdr_t)) < 0) {
        ERROR("Cannot load XCOFF AOUT header...\n");
        return -1;
    }
    if (ahdr.magic != AOUT_MAGIC) {
        ERROR("Invalid AOUT optional header\n");
        return -2;
    }
#if 0 // XXX: buggy: this makes NetBSD fail to boot
    if (fhdr.f_magic == 0x01DF) {
        /* Load embedded file */
        return _bootfile_load(file, dest, entry, end, loffset +
                              sizeof(COFF_filehdr_t) + sizeof(COFF_aouthdr_t) +
                              (fhdr.f_nscns * sizeof(COFF_scnhdr_t)),
                              -1);
    }
#endif
    *entry = (void *)ahdr.entry + 0xC;
    last = NULL;
    first = last - 4;
    offset = sizeof(COFF_filehdr_t) + sizeof(COFF_aouthdr_t);
    DPRINTF("XCOFF file with %d sections entry:%p\n", fhdr.f_nscns, *entry);
    for (i = 0; i < fhdr.f_nscns; i++) {
        DPRINTF("Read next header (%0x)\n", offset);
        file_seek(file, offset + loffset);
        if (fs_read(file, &shdr, sizeof(COFF_scnhdr_t)) < 0) {
            ERROR("Cannot load section header %d...\n", i);
            return -1;
        }
	if (strcmp(shdr.s_name, ".text") == 0 ||
            strcmp(shdr.s_name, ".data") == 0) {
            if ((void *)shdr.s_vaddr < first)
                first = (void *)shdr.s_vaddr;
            if ((void *)shdr.s_vaddr > last)
                last = (void *)shdr.s_vaddr;
            DPRINTF("Load '%s' section from %0x %0x to %0x (%0x)\n",
                    shdr.s_name, offset, shdr.s_scnptr,
                    shdr.s_vaddr, shdr.s_size);
#if 0
            if (shdr.s_scnptr + shdr.s_size > fs_inode_get_size(file)) {
                ERROR("Section %d data offset > file size\n", i);
                return -1;
            }
#endif
            file_seek(file, shdr.s_scnptr + loffset);
            set_loadinfo((void *)first, last - first);
            if (fs_read(file, (void *)shdr.s_vaddr, shdr.s_size) < 0) {
                ERROR("Cannot load section %d...\n", i);
                return -1;
            }
        } else if (strcmp(shdr.s_name, ".bss") == 0) {
            if ((void *)shdr.s_vaddr < first)
                first = (void *)shdr.s_vaddr;
            if ((void *)shdr.s_vaddr > last)
                last = (void *)shdr.s_vaddr;
            DPRINTF("Erase '%s' section at %0x size: %0x\n",
                    shdr.s_name, shdr.s_vaddr, shdr.s_size);
            memset((void *)shdr.s_vaddr, 0, shdr.s_size);
        } else {
            DPRINTF("Skip '%s' section\n", shdr.s_name);
        }
        offset += sizeof(COFF_scnhdr_t);
    }
    *dest = first;
    *end = last;

    return 0;
}
