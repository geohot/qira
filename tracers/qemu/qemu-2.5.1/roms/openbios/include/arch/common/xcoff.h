#ifndef XCOFF_H
#define XCOFF_H

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

#define U802WRMAGIC	 0x02DA	/* writeable text segments **chh**	  */
#define U802ROMAGIC	 0x02DF	/* readonly sharable text segments	  */
#define U802TOCMAGIC	 0x02E1	/* readonly text segments and TOC	   */
#define U802TOMAGIC	 0x01DF

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

#define	COFF_F_RELFLG		0000001
#define	COFF_F_EXEC		0000002
#define	COFF_F_LNNO		0000004
#define	COFF_F_LSYMS		0000010
#define	COFF_F_MINMAL		0000020
#define	COFF_F_UPDATE		0000040
#define	COFF_F_SWABD		0000100
#define	COFF_F_AR16WR		0000200
#define	COFF_F_AR32WR		0000400
#define	COFF_F_AR32W		0001000
#define	COFF_F_PATCH		0002000
#define	COFF_F_NODF		0002000

typedef struct COFF_aouthdr_t {
	uint16_t magic;	     /* type of file			      */
	uint16_t vstamp;     /* version stamp			      */
	uint32_t tsize;	     /* text size in bytes, padded to FW bdry */
	uint32_t dsize;	     /* initialized data "  "		      */
	uint32_t bsize;	     /* uninitialized data "   "	      */
	uint32_t entry;	     /* entry pt.			      */
	uint32_t text_start; /* base of text used for this file	      */
	uint32_t data_start; /* base of data used for this file	      */
	uint32_t o_toc;	     /* address of TOC			      */
	uint16_t o_snentry;  /* section number of entry point	      */
	uint16_t o_sntext;   /* section number of .text section	      */
	uint16_t o_sndata;   /* section number of .data section	      */
	uint16_t o_sntoc;    /* section number of TOC		      */
	uint16_t o_snloader; /* section number of .loader section     */
	uint16_t o_snbss;    /* section number of .bss section	      */
	uint16_t o_algntext; /* .text alignment			      */
	uint16_t o_algndata; /* .data alignment			      */
	uint16_t o_modtype;  /* module type (??)		      */
	uint16_t o_cputype;  /* cpu type			      */
	uint32_t o_maxstack; /* max stack size (??)		      */
	uint32_t o_maxdata;  /* max data size (??)		      */
	char o_resv2[12];    /* reserved			      */
} COFF_aouthdr_t;

#define AOUT_MAGIC	0x010b

typedef struct COFF_scnhdr_t {
	char s_name[8];		/* section name				*/
	uint32_t s_paddr;	/* physical address, aliased s_nlib     */
	uint32_t s_vaddr;	/* virtual address			*/
	uint32_t s_size;	/* section size				*/
	uint32_t s_scnptr;	/* file ptr to raw data for section     */
	uint32_t s_relptr;	/* file ptr to relocation		*/
	uint32_t s_lnnoptr;	/* file ptr to line numbers		*/
	uint16_t s_nreloc;	/* number of relocation entries		*/
	uint16_t s_nlnno;	/* number of line number entries	*/
	uint32_t s_flags;	/* flags				*/
} COFF_scnhdr_t;

#endif /* XCOFF_H */
