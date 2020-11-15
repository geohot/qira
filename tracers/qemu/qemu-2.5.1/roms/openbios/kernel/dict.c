/*
 * tag: dict management
 *
 * Copyright (C) 2003-2005 Stefan Reinauer, Patrick Mauritz
 *
 * See the file "COPYING" for further information about
 * the copyright and warranty status of this work.
 */

#include "config.h"
#include "kernel/kernel.h"
#include "dict.h"
#ifdef BOOTSTRAP
#include <string.h>
#else
#include "libc/string.h"
#endif
#include "cross.h"


unsigned char *dict = NULL;
ucell *last;
cell dicthead = 0;
cell dictlimit = 0;

/* lfa2nfa
 * converts a link field address to a name field address,
 * i.e find pointer to a given words name
 */

ucell lfa2nfa(ucell ilfa)
{
	/* get offset from dictionary start */
	ilfa = ilfa - (ucell)pointer2cell(dict);
	ilfa--;				/* skip status        */
	while (dict[--ilfa] == 0);	/* skip all pad bytes */
	ilfa -= (dict[ilfa] - 128);
	return ilfa + (ucell)pointer2cell(dict);
}

/* lfa2cfa
 * converts a link field address to a code field address.
 * in this forth implementation this is just a fixed offset
 */

static xt_t lfa2cfa(ucell ilfa)
{
	return (xt_t)(ilfa + sizeof(cell));
}


/* fstrlen - returns length of a forth string. */

ucell fstrlen(ucell fstr)
{
	fstr -= pointer2cell(dict)+1;
	//fstr -= pointer2cell(dict); FIXME
	while (dict[++fstr] < 128)
		;
	return dict[fstr] - 128;
}

/* to_lower - convert a character to lowecase */

static int to_lower(int c)
{
	return ((c >= 'A') && (c <= 'Z')) ? (c - 'A' + 'a') : c;
}

/* fstrcmp - compare null terminated string with forth string. */

static int fstrcmp(const char *s1, ucell fstr)
{
	char *s2 = (char*)cell2pointer(fstr);
	while (*s1) {
		if ( to_lower(*(s1++)) != to_lower(*(s2++)) )
			return -1;
	}
	return 0;
}

/* fstrncpy - copy a forth string to a destination (with NULL termination) */

void fstrncpy(char *dest, ucell src, unsigned int maxlen)
{
	int len = fstrlen(src);

	if (fstrlen(src) >= maxlen) len = maxlen - 1;
	memcpy(dest, cell2pointer(src), len);
	*(dest + len) = '\0';
} 


/* findword
 * looks up a given word in the dictionary. This function
 * is used by the c based interpreter and to find the "initialize"
 * word.
 */

xt_t findword(const char *s1)
{
	ucell tmplfa, len;

	if (!last)
		return 0;

	tmplfa = read_ucell(last);

	len = strlen(s1);

	while (tmplfa) {
		ucell nfa = lfa2nfa(tmplfa);

		if (len == fstrlen(nfa) && !fstrcmp(s1, nfa)) {
			return lfa2cfa(tmplfa);
		}

		tmplfa = read_ucell(cell2pointer(tmplfa));
	}

	return 0;
}


/* findsemis_wordlist
 * Given a DOCOL xt and a wordlist, find the address of the semis
 * word at the end of the word definition. We do this by finding
 * the word before this in the dictionary, then counting back one
 * from the NFA.
 */

static ucell findsemis_wordlist(ucell xt, ucell wordlist)
{
	ucell tmplfa, nextlfa, nextcfa;

	if (!wordlist)
		return 0;

	tmplfa = read_ucell(cell2pointer(wordlist));
	nextcfa = lfa2cfa(tmplfa);

	/* Catch the special case where the lfa of the word we
	 * want is the last word in the dictionary; in that case
	 * the end of the word is given by "here" - 1 */
	if (nextcfa == xt)
		return pointer2cell(dict) + dicthead - sizeof(cell);

	while (tmplfa) {

		/* Peek ahead and see if the next CFA in the list is the
		 * one we are searching for */ 
		nextlfa = read_ucell(cell2pointer(tmplfa)); 
		nextcfa = lfa2cfa(nextlfa);

		/* If so, count back 1 cell from the current NFA */
		if (nextcfa == xt)
			return lfa2nfa(tmplfa) - sizeof(cell);

		tmplfa = nextlfa;
	}

	return 0;
}


/* findsemis
 * Given a DOCOL xt, find the address of the semis word at the end
 * of the word definition by searching all vocabularies */

ucell findsemis(ucell xt)
{
	ucell usesvocab = findword("vocabularies?") + sizeof(cell);
	unsigned int i;

	if (read_ucell(cell2pointer(usesvocab))) {
		/* Vocabularies are in use, so search each one in turn */
		ucell numvocabs = findword("#order") + sizeof(cell);

		for (i = 0; i < read_ucell(cell2pointer(numvocabs)); i++) {
			ucell vocabs = findword("vocabularies") + 2 * sizeof(cell);
			ucell semis = findsemis_wordlist(xt, read_cell(cell2pointer(vocabs + (i * sizeof(cell))))); 	

			/* If we get a non-zero result, we found the xt in this vocab */
			if (semis)
				return semis;
		}
	} else { 
		/* Vocabularies not in use */
		return findsemis_wordlist(xt, read_ucell(last));
	}

	return 0;
}


/* findxtfromcell_wordlist
 * Given a cell and a wordlist, determine the CFA of the word containing
 * the cell or 0 if we are unable to return a suitable CFA
 */

ucell findxtfromcell_wordlist(ucell incell, ucell wordlist)
{
	ucell tmplfa;

	if (!wordlist)
		return 0;

	tmplfa = read_ucell(cell2pointer(wordlist));
	while (tmplfa) {
		if (tmplfa < incell)
			return lfa2cfa(tmplfa);

		tmplfa = read_ucell(cell2pointer(tmplfa));
	}	

	return 0;
} 


/* findxtfromcell
 * Given a cell, determine the CFA of the word containing
 * the cell by searching all vocabularies 
 */

ucell findxtfromcell(ucell incell)
{
	ucell usesvocab = findword("vocabularies?") + sizeof(cell);
	unsigned int i;

	if (read_ucell(cell2pointer(usesvocab))) {
		/* Vocabularies are in use, so search each one in turn */
		ucell numvocabs = findword("#order") + sizeof(cell);

		for (i = 0; i < read_ucell(cell2pointer(numvocabs)); i++) {
			ucell vocabs = findword("vocabularies") + 2 * sizeof(cell);
			ucell semis = findxtfromcell_wordlist(incell, read_cell(cell2pointer(vocabs + (i * sizeof(cell))))); 	

			/* If we get a non-zero result, we found the xt in this vocab */
			if (semis)
				return semis;
		}
	} else { 
		/* Vocabularies not in use */
		return findxtfromcell_wordlist(incell, read_ucell(last));
	}

	return 0;
}

void dump_header(dictionary_header_t *header)
{
	printk("OpenBIOS dictionary:\n");
	printk("  version:     %d\n", header->version);
	printk("  cellsize:    %d\n", header->cellsize);
	printk("  endianess:   %s\n", header->endianess?"big":"little");
	printk("  compression: %s\n", header->compression?"yes":"no");
	printk("  relocation:  %s\n", header->relocation?"yes":"no");
	printk("  checksum:    %08x\n", target_long(header->checksum));
	printk("  length:      %08x\n", target_long(header->length));
	printk("  last:        %0" FMT_CELL_x "\n", target_cell(header->last));
}

ucell load_dictionary(const char *data, ucell len)
{
	u32 checksum=0;
	const char *checksum_walk;
	ucell *walk, *reloc_table;
	dictionary_header_t *header=(dictionary_header_t *)data;

	/* assertions */
	if (len <= (sizeof(dictionary_header_t)) || strncmp(DICTID, data, 8))
		return 0;
#ifdef CONFIG_DEBUG_DICTIONARY
	dump_header(header);
#endif

	checksum_walk=data;
	while (checksum_walk<data+len) {
		checksum+=read_long(checksum_walk);
		checksum_walk+=sizeof(u32);
	}

	if(checksum) {
		printk("Checksum invalid (%08x)!\n", checksum);
		return 0;
	}

	data += sizeof(dictionary_header_t);

	dicthead = target_long(header->length);

	memcpy(dict, data, dicthead);
	reloc_table=(ucell *)(data+dicthead);

#ifdef CONFIG_DEBUG_DICTIONARY
	printk("\nmoving dictionary (%x bytes) to %x\n",
			(ucell)dicthead, (ucell)dict);
	printk("\ndynamic relocation...");
#endif

	for (walk = (ucell *) dict; walk < (ucell *) (dict + dicthead);
	     walk++) {
		int pos, bit, l;
		l=(walk-(ucell *)dict);
		pos=l/BITS;
		bit=l&~(-BITS);
                if (reloc_table[pos] & target_ucell((ucell)1ULL << bit)) {
			// printk("%lx, pos %x, bit %d\n",*walk, pos, bit);
			write_ucell(walk, read_ucell(walk)+pointer2cell(dict));
		}
	}

#ifdef CONFIG_DEBUG_DICTIONARY
	printk(" done.\n");
#endif

	last = (ucell *)(dict + target_ucell(header->last));

	return -1;
}
