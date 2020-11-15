#ifndef COFF_H
#define COFF_H
/* Based on the elf.h file
 * Changed accordingly to support COFF file support
 */


/* Values for f_flags. */
#define F_RELFLG	0x0001 	/* If set, not reloc. info. Clear for executables */
#define F_EXEC		0x0002	/* No unresolved symbols. Executable file ! */
#define F_LNNO		0x0004	/* If set, line information numbers removed  */
#define F_LSYMS		0x0008	/* If set, local symbols removed  */
#define F_AR32WR	0x0100	/* Indicates little endian file */

/* Values for e_machine (architecute). */
#define EM_E1		0x17a 	/* Magic number for Hyperstone. Big endian format */

/* Values for f_flags. */
#define	O_MAGIC		0x017c	/* Optional's header magic number for Hyperstone */

/* Values for s_flags. */
#define S_TYPE_TEXT	0x0020 	/* If set, the section contains only executable */
#define S_TYPE_DATA	0x0040 	/* If set, the section contains only initialized data */
#define S_TYPE_BSS	0x0080 	/* If set, the section is BSS no data stored */


typedef struct
{
	unsigned short 	f_magic;	/* magic number				*/
	unsigned short 	f_nscns;	/* number of sections		*/
	unsigned long 	f_timdat;	/* time & date stamp		*/
	unsigned long 	f_symptr;	/* file pointer to symtab	*/
	unsigned long 	f_nsyms;	/* number of symtab entries	*/
	unsigned short	f_opthdr;	/* sizeof(optional hdr)		*/
	unsigned short 	f_flags;	/* flags					*/
}
COFF_filehdr;

/*
 * Optional header.
 */
typedef struct 
{
  unsigned short	magic;		/* type of file				*/
  unsigned short	vstamp;		/* version stamp			*/
  unsigned long		tsize;		/* text size in bytes, padded to FW bdry*/
  unsigned long		dsize;		/* initialized data "  "		*/
  unsigned long		bsize;		/* uninitialized data "   "		*/
  unsigned long		entry;		/* entry pt.				*/
  unsigned long		text_start;	/* base of text used for this file */
  unsigned long 	data_start;	/* base of data used for this file */
}	
COFF_opthdr;

/*
 * Section header.
 */
typedef struct 
{
	char				s_name[8];	/* section name			*/
	unsigned long		s_paddr;	/* physical address, aliased s_nlib */
	unsigned long		s_vaddr;	/* virtual address		*/
	unsigned long		s_size;		/* section size			*/
	unsigned long		s_scnptr;	/* file ptr to raw data for section */
	unsigned long		s_relptr;	/* file ptr to relocation	*/
	unsigned long		s_lnnoptr;	/* file ptr to line numbers	*/
	unsigned short		s_nreloc;	/* number of relocation entries	*/
	unsigned short		s_nlnno;	/* number of line number entries*/
	unsigned long		s_flags;	/* flags			*/
}
COFF_scnhdr;

#endif /* COFF_H */
