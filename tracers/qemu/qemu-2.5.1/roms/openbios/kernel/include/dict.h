/* tag: dict management headers
 *
 * Copyright (C) 2003 Patrick Mauritz, Stefan Reinauer
 *
 * See the file "COPYING" for further information about
 * the copyright and warranty status of this work.
 */

#ifndef __DICT_H
#define __DICT_H

#define DICTID "OpenBIOS"

#define DOSEMIS 0
#define DOCOL   1
#define DOLIT   2
#define DOCON   3
#define DOVAR   4
#define DODFR   5
#define DODOES  6

#define MAXNFALEN 128

/* The header is 28/32 bytes on 32/64bit platforms */

typedef struct dictionary_header {
	char	signature[8];
	u8	version;
	u8	cellsize;
	u8 	endianess;
	u8	compression;
	u8	relocation;
	u8	reserved[3];
	u32	checksum;
	u32	length;
	ucell	last;
} __attribute__((packed)) dictionary_header_t;

ucell lfa2nfa(ucell ilfa);
ucell load_dictionary(const char *data, ucell len);
void  dump_header(dictionary_header_t *header);
ucell fstrlen(ucell fstr);
void fstrncpy(char *dest, ucell src, unsigned int maxlen);
ucell findsemis(ucell xt);
ucell findxtfromcell_wordlist(ucell incell, ucell wordlist);
ucell findxtfromcell(ucell incell);

/* program counter */
extern ucell 		PC;

extern unsigned char	*dict;
extern cell 		dicthead;
extern cell		dictlimit;
extern ucell		*last;
#ifdef FCOMPILER
extern ucell *trampoline;
#endif

#endif
