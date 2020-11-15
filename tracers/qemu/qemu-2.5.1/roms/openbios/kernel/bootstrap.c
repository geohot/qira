/* tag: forth bootstrap environment
 *
 * Copyright (C) 2003-2006 Stefan Reinauer, Patrick Mauritz
 *
 * See the file "COPYING" for further information about
 * the copyright and warranty status of this work.
 */

#include "sysinclude.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <termios.h>
#include <sys/stat.h>

#ifdef __GLIBC__
#define _GNU_SOURCE
#include <getopt.h>
#endif

#include "config.h"
#include "kernel/stack.h"
#include "sysinclude.h"
#include "kernel/kernel.h"
#include "dict.h"
#include "cross.h"
#include "openbios-version.h"

#define MAX_PATH_LEN 256

#define MEMORY_SIZE (1024*1024)	/* 1M ram for hosted system */
#define DICTIONARY_SIZE (256*1024) /* 256k for the dictionary   */
#define TRAMPOLINE_SIZE (4*sizeof(cell)) /* 4 cells for the trampoline */

/* state variables */
static ucell *latest, *state, *base;
static ucell *memory;
ucell *trampoline;

/* local variables */
static int errors = 0;
static int segfault = 0;
static int verbose = 0;

#define MAX_SRC_FILES 128

static FILE *srcfiles[MAX_SRC_FILES];
static char *srcfilenames[MAX_SRC_FILES];
static int srclines[MAX_SRC_FILES];
static unsigned int cursrc = 0;

static char *srcbasedict;

/* console variables */
static FILE *console;

#ifdef NATIVE_BITWIDTH_SMALLER_THAN_HOST_BITWIDTH
unsigned long base_address;
#endif

/* include path handling */
typedef struct include_path include;
struct include_path {
        const char *path;
	include *next;
};

static include includes = { ".", NULL };
static FILE *depfile;

static ucell * relocation_address=NULL;
static int     relocation_length=0;

/* the word names are used to generate the prim words in the
 * dictionary. This is done by the C written interpreter.
 */
static const char *wordnames[] = {
	"(semis)", "", "(lit)", "", "", "", "", "(do)", "(?do)", "(loop)",
	"(+loop)", "", "", "", "dup", "2dup", "?dup", "over", "2over", "pick", "drop",
	"2drop", "nip", "roll", "rot", "-rot", "swap", "2swap", ">r", "r>",
	"r@", "depth", "depth!", "rdepth", "rdepth!", "+", "-", "*", "u*",
	"mu/mod", "abs", "negate", "max", "min", "lshift", "rshift", ">>a",
	"and", "or", "xor", "invert", "d+", "d-", "m*", "um*", "@", "c@",
	"w@", "l@", "!", "+!", "c!", "w!", "l!", "=", ">", "<", "u>", "u<",
	"sp@", "move", "fill", "(emit)", "(key?)", "(key)", "execute",
	"here", "here!", "dobranch", "do?branch", "unaligned-w@",
	"unaligned-w!", "unaligned-l@", "unaligned-l!", "ioc@", "iow@",
	"iol@", "ioc!", "iow!", "iol!", "i", "j", "call", "sys-debug",
	"$include", "$encode-file", "(debug", "(debug-off)"
};

/*
 * dictionary related functions.
 */

/*
 * Compare two dictionaries constructed at different addresses. When
 * the cells don't match, a need for relocation is detected and the
 * corresponding bit in reloc_table bitmap is set.
 */
static void relocation_table(unsigned char * dict_one, unsigned char *dict_two, int length)
{
	ucell *d1=(ucell *)dict_one, *d2=(ucell *)dict_two;
	ucell *reloc_table;
	int pos, bit;
	int l=(length+(sizeof(cell)-1))/sizeof(ucell), i;

	/* prepare relocation table */
	relocation_length=(length+BITS-1)/BITS;
	reloc_table = malloc(relocation_length*sizeof(cell));
	memset(reloc_table,0,relocation_length*sizeof(cell));

	for (i=0; i<l; i++) {

		pos=i/BITS;
		bit=i&~(-BITS);

		if(d1[i]==d2[i]) {
                        reloc_table[pos] &= target_ucell(~((ucell)1ULL << bit));

			// This check might bring false positives in data.
			//if(d1[i] >= pointer2cell(dict_one) &&
			//		d1[i] <= pointer2cell(dict_one+length))
			//	printk("\nWARNING: inconsistent relocation (%x:%x)!\n", d1[i], d2[i]);
		} else {
			/* This is a pointer, it needs relocation, d2==dict */
                        reloc_table[pos] |= target_ucell((ucell)1ULL << bit);
			d2[i] = target_ucell(target_ucell(d2[i]) - pointer2cell(d2));
		}
	}

#ifdef CONFIG_DEBUG_DICTIONARY
	printk("dict1 %lx dict2 %lx dict %lx\n",dict_one, dict_two, dict);
	for (i=0; i< relocation_length ; i++)
		printk("reloc %d %lx\n",i+1, reloc_table[i]);
#endif
	relocation_address=reloc_table;
}

static void write_dictionary(const char *filename)
{
	FILE *f;
	unsigned char *write_data, *walk_data;
	int  write_len;
	dictionary_header_t *header;
	u32 checksum=0;

	/*
	 * get memory for dictionary
	 */

	write_len  = sizeof(dictionary_header_t)+dicthead+relocation_length*sizeof(cell);
	write_data = malloc(write_len);
	if(!write_data) {
		printk("panic: can't allocate memory for output dictionary (%d"
			" bytes\n", write_len);
		exit(1);
	}
	memset(write_data, 0, write_len);

	/*
	 * prepare dictionary header
	 */

	header = (dictionary_header_t *)write_data;
	*header = (dictionary_header_t){
		.signature	= DICTID,
		.version	= 2,
		.cellsize	= sizeof(ucell),
#ifdef CONFIG_BIG_ENDIAN
		.endianess	= -1,
#else
		.endianess	= 0,
#endif
		.checksum	= 0,
		.compression	= 0,
		.relocation	= -1,
                .length         = target_ulong((uint32_t)dicthead),
                .last           = target_ucell((ucell)((unsigned long)last
                                                       - (unsigned long)dict)),
	};

	/*
	 * prepare dictionary data
	 */

	walk_data=write_data+sizeof(dictionary_header_t);
	memcpy (walk_data, dict, dicthead);

	/*
	 * prepare relocation data.
	 * relocation_address is zero when writing a dictionary core.
	 */

	if (relocation_address) {
#ifdef CONFIG_DEBUG_DICTIONARY
		printk("writing %d reloc cells \n",relocation_length);
#endif
		walk_data += dicthead;
		memcpy(walk_data, relocation_address,
				relocation_length*sizeof(cell));
		/* free relocation information */
		free(relocation_address);
		relocation_address=NULL;
	} else {
		header->relocation=0;
	}

	/*
	 * Calculate Checksum
	 */

	walk_data=write_data;
	while (walk_data<write_data+write_len) {
		checksum+=read_long(walk_data);
		walk_data+=sizeof(u32);
	}
	checksum=(u32)-checksum;

	header->checksum=target_long(checksum);

        if (verbose) {
                dump_header(header);
        }

	f = fopen(filename, "w");
	if (!f) {
		printk("panic: can't write to dictionary '%s'.\n", filename);
		exit(1);
	}

	fwrite(write_data, write_len, 1, f);

	free(write_data);
	fclose(f);

#ifdef CONFIG_DEBUG_DICTIONARY
	printk("wrote dictionary to file %s.\n", filename);
#endif
}

/*
 * Write dictionary as a list of ucell hex values to filename. Array
 * header and end lines are not generated.
 *
 * Cells with relocations are output using the expression
 * DICTIONARY_BASE + value.
 *
 * Define some helpful constants.
 */
static void write_dictionary_hex(const char *filename)
{
    FILE *f;
    ucell *walk;

    f = fopen(filename, "w");
    if (!f) {
        printk("panic: can't write to dictionary '%s'.\n", filename);
        exit(1);
    }

    for (walk = (ucell *)dict; walk < (ucell *)(dict + dicthead); walk++) {
        int pos, bit, l;
        ucell val;

        l = (walk - (ucell *)dict);
        pos = l / BITS;
        bit = l & ~(-BITS);

        val = read_ucell(walk);
        if (relocation_address[pos] & target_ucell((ucell)1ULL << bit)) {
            fprintf(f, "DICTIONARY_BASE + 0x%" FMT_CELL_x
                    ",\n", val);
        } else {
            fprintf(f, "0x%" FMT_CELL_x",\n", val);
        }
    }

    fprintf(f, "#define FORTH_DICTIONARY_LAST 0x%" FMT_CELL_x"\n",
            (ucell)((unsigned long)last - (unsigned long)dict));
    fprintf(f, "#define FORTH_DICTIONARY_END 0x%" FMT_CELL_x"\n",
            (ucell)dicthead);
    fclose(f);

#ifdef CONFIG_DEBUG_DICTIONARY
    printk("wrote dictionary to file %s.\n", filename);
#endif
}

static ucell read_dictionary(char *fil)
{
	int ilen;
	ucell ret;
	char *mem;
	FILE *f;
	struct stat finfo;

	if (stat(fil, &finfo))
		return 0;

	ilen = finfo.st_size;

	if ((mem = malloc(ilen)) == NULL) {
		printk("panic: not enough memory.\n");
		exit(1);
	}

	f = fopen(fil, "r");
	if (!f) {
		printk("panic: can't open dictionary.\n");
		exit(1);
	}

	if (fread(mem, ilen, 1, f) != 1) {
		printk("panic: can't read dictionary.\n");
		fclose(f);
		exit(1);
	}
	fclose(f);

	ret = load_dictionary(mem, ilen);

	free(mem);
	return ret;
}


/*
 * C Parser related functions
 */

/*
 * skipws skips all whitespaces (space, tab, newline) from the input file
 */

static void skipws(FILE * f)
{
	int c;
	while (!feof(f)) {
		c = getc(f);

		if (c == ' ' || c == '\t')
			continue;

		if (c == '\n') {
			srclines[cursrc - 1]++;
			continue;
		}

		ungetc(c, f);
		break;
	}
}

/*
 * parse gets the next word from the input stream, delimited by
 * delim. If delim is 0, any word delimiter will end the stream
 * word delimiters are space, tab and newline. The resulting word
 * will be put zero delimited to the char array line.
 */

static int parse(FILE * f, char *line, char delim)
{
	int cnt = 0, c = 0;

	while (!feof(f)) {
		c = getc(f);

		if (delim && c == delim)
			break;

		if ((!delim) && (c == ' ' || c == '\t' || c == '\n'))
			break;

		line[cnt++] = c;
	}

	/* Update current line number */
	if (c == '\n') {
		srclines[cursrc - 1]++;
	}

	line[cnt] = 0;

	return cnt;
}

/*
 * parse_word is a small helper that skips whitespaces before a word.
 * it's behaviour is similar to the forth version parse-word.
 */

static void parse_word(FILE * f, char *line)
{
	skipws(f);
	parse(f, line, 0);
}


static void writestring(const char *str)
{
	unsigned int i;
	for (i = 0; i < strlen(str); i++) {
		dict[dicthead + i] = str[i];
	}
	dicthead += i + 1;
	dict[dicthead - 1] = (char) strlen(str) + 128;
}

#define writebyte(value) {write_byte(dict+dicthead,value); dicthead++;}
#define writecell(value) {write_cell(dict+dicthead, value); dicthead+=sizeof(cell);}

/*
 * reveal a word, ie. make it visible.
 */

static void reveal(void)
{
	*last = *latest;
}

/*
 * dictionary padding
 */

static void paddict(ucell align)
{
	while (dicthead % align != 0)
		writebyte(0);
}

/*
 * generic forth word creator function.
 */

static void fcreate(const char *word, ucell cfaval)
{
	if (strlen(word) == 0) {
		printk("WARNING: tried to create unnamed word.\n");
		return;
	}

	writestring(word);
	/* get us at least 1 byte for flags */
	writebyte(0);
	paddict(sizeof(cell));
	/* set flags high bit. */
	dict[dicthead - 1] = 128;
	/* lfa and cfa */
	writecell(read_ucell(latest));
	*latest = target_ucell(pointer2cell(dict) + dicthead - sizeof(cell));
	writecell(cfaval);
}


static ucell *buildvariable(const char *name, cell defval)
{
	fcreate(name, DOVAR);	/* see dict.h for DOVAR and other CFA ids */
	writecell(defval);
	return (ucell *) (dict + dicthead - sizeof(cell));
}

static void buildconstant(const char *name, cell defval)
{
	fcreate(name, DOCON);	/* see dict.h for DOCON and other CFA ids */
	writecell(defval);
}

static void builddefer(const char *name)
{
	fcreate(name, DODFR);	/* see dict.h for DODFR and other CFA ids */
        writecell((ucell)0);
	writecell((ucell)findword("(semis)"));
}

/*
 * Include file handling
 */

static void add_includepath(char *path)
{
	include *incl = &includes;
	include *newpath;

	while (incl->next)
		incl = incl->next;

	newpath = malloc(sizeof(include));
	if (!newpath) {
		printk("panic: not enough memory for include path.\n");
		exit(1);
	}

	incl->next = newpath;
	newpath->path = path;
	newpath->next = NULL;
}


static FILE *fopen_include(const char *fil)
{
	char fullpath[MAX_PATH_LEN];
	FILE *ret;
	include *incl = &includes;

	while (incl) {
                snprintf(fullpath, sizeof(fullpath), "%s/%s", incl->path, fil);

		ret = fopen(fullpath, "r");
		if (ret != NULL) {

#ifdef CONFIG_DEBUG_INTERPRETER
			printk("Including '%s'\n", fil);
#endif
			srcfilenames[cursrc] = strdup(fil);
			srclines[cursrc] = 1;
			srcfiles[cursrc++] = ret;

                        if (depfile) {
                                fprintf(depfile, " %s", fullpath);
                        }

			return ret;
		}

		incl = incl->next;
	}
	return NULL;
}


/*
 * Forth exception handler
 */

void exception(cell no)
{
	printk("%s:%d: ", srcfilenames[cursrc - 1], srclines[cursrc - 1]);

	/* See also forth/bootstrap/interpreter.fs */
	switch (no) {
	case -1:
	case -2:
		printk("Aborted.\n");
		break;
	case -3:
		printk("Stack Overflow.\n");
		break;
	case -4:
		printk("Stack Underflow.\n");
		break;
	case -5:
		printk("Return Stack Overflow.\n");
		break;
	case -6:
		printk("Return Stack Underflow.\n");
		break;
	case -19:
		printk("undefined word.\n");
		break;
	case -21:
		printk("out of memory.\n");
		break;
	case -33:
		printk("undefined method.\n");
		break;
	case -34:
		printk("no such device.\n");
		break;
	default:
		printk("error %" FMT_CELL_d " occured.\n", no);
	}
	exit(1);
}


/*
 * This is the C version of the forth interpreter
 */

static int interpret_source(char *fil)
{
	FILE *f;
	char tib[160];
        cell num;
	char *test;

	const ucell SEMIS = (ucell)findword("(semis)");
	const ucell LIT = (ucell)findword("(lit)");
	const ucell DOBRANCH = (ucell)findword("dobranch");

	if ((f = fopen_include(fil)) == NULL) {
		printk("error while loading source file '%s'\n", fil);
		errors++;
		exit(1);
	}

	/* FIXME: We should read this file at
	 * once. No need to get it char by char
	 */

	while (!feof(f)) {
		xt_t res;
		parse_word(f, tib);

		/* if there is actually no word, we continue right away */
		if (strlen(tib) == 0) {
			continue;
		}

		/* Checking for builtin words that are needed to
		 * bootstrap the forth base dictionary.
		 */

		if (!strcmp(tib, "(")) {
			parse(f, tib, ')');
			continue;
		}

		if (!strcmp(tib, "\\")) {
			parse(f, tib, '\n');
			continue;
		}

		if (!strcmp(tib, ":")) {
			parse_word(f, tib);

#ifdef CONFIG_DEBUG_INTERPRETER
			printk("create colon word %s\n\n", tib);
#endif
			fcreate(tib, DOCOL);	/* see dict.h for DOCOL and other CFA ids */
			*state = (ucell) (-1);
			continue;
		}

		if (!strcmp(tib, ";")) {
#ifdef CONFIG_DEBUG_INTERPRETER
			printk("finish colon definition\n\n");
#endif
			writecell((cell)SEMIS);
			*state = (ucell) 0;
			reveal();
			continue;
		}

		if (!strcasecmp(tib, "variable")) {
			parse_word(f, tib);
#ifdef CONFIG_DEBUG_INTERPRETER
			printk("defining variable %s\n\n", tib);
#endif
			buildvariable(tib, 0);
			reveal();
			continue;
		}

		if (!strcasecmp(tib, "constant")) {
			parse_word(f, tib);
#ifdef CONFIG_DEBUG_INTERPRETER
			printk("defining constant %s\n\n", tib);
#endif
			buildconstant(tib, POP());
			reveal();
			continue;
		}

		if (!strcasecmp(tib, "value")) {
			parse_word(f, tib);
#ifdef CONFIG_DEBUG_INTERPRETER
			printk("defining value %s\n\n", tib);
#endif
			buildconstant(tib, POP());
			reveal();
			continue;
		}

		if (!strcasecmp(tib, "defer")) {
			parse_word(f, tib);
#ifdef CONFIG_DEBUG_INTERPRETER
			printk("defining defer word %s\n\n", tib);
#endif
			builddefer(tib);
			reveal();
			continue;
		}

		if (!strcasecmp(tib, "include")) {
			parse_word(f, tib);
#ifdef CONFIG_DEBUG_INTERPRETER
			printk("including file %s\n\n", tib);
#endif
			interpret_source(tib);
			continue;
		}

		if (!strcmp(tib, "[']")) {
			xt_t xt;
			parse_word(f, tib);
			xt = findword(tib);
			if (*state == 0) {
#ifdef CONFIG_DEBUG_INTERPRETER
				printk
				    ("writing address of %s to stack\n\n",
				     tib);
#endif
				PUSH_xt(xt);
			} else {
#ifdef CONFIG_DEBUG_INTERPRETER
				printk("writing lit, addr(%s) to dict\n\n",
				       tib);
#endif
				writecell(LIT);	/* lit */
				writecell((cell)xt);
			}
			continue;
			/* we have no error detection here */
		}

		if (!strcasecmp(tib, "s\"")) {
			int cnt;
			cell loco;

			cnt = parse(f, tib, '"');
#ifdef CONFIG_DEBUG_INTERPRETER
			printk("compiling string %s\n", tib);
#endif
			loco = dicthead + (6 * sizeof(cell));
			writecell(LIT);
			writecell(pointer2cell(dict) + loco);
			writecell(LIT);
                        writecell((ucell)cnt);
			writecell(DOBRANCH);
			loco = cnt + sizeof(cell) - 1;
			loco &= ~(sizeof(cell) - 1);
			writecell(loco);
			memcpy(dict + dicthead, tib, cnt);
			dicthead += cnt;
			paddict(sizeof(cell));
			continue;
		}

		/* look if tib is in dictionary. */
		/* should the dictionary be searched before the builtins ? */
		res = findword(tib);
		if (res) {
			u8 flags = read_byte((u8*)cell2pointer(res) -
						sizeof(cell) - 1);
#ifdef CONFIG_DEBUG_INTERPRETER
                        printk("%s is 0x%" FMT_CELL_x "\n", tib, (ucell) res);
#endif
			if (!(*state) || (flags & 3)) {
#ifdef CONFIG_DEBUG_INTERPRETER
                                printk("executing %s, %" FMT_CELL_d
                                       " (flags: %s %s)\n",
				       tib, res,
				       (flags & 1) ? "immediate" : "",
				       (flags & 2) ? "compile-only" : "");
#endif
				PC = (ucell)res;
				enterforth(res);
			} else {
#ifdef CONFIG_DEBUG_INTERPRETER
				printk("writing %s to dict\n\n", tib);
#endif
				writecell((cell)res);
			}
			continue;
		}

		/* if not look if it's a number */
		if (tib[0] == '-')
			num = strtoll(tib, &test, read_ucell(base));
		else
			num = strtoull(tib, &test, read_ucell(base));


		if (*test != 0) {
			/* what is it?? */
			printk("%s:%d: %s is not defined.\n\n", srcfilenames[cursrc - 1], srclines[cursrc - 1], tib);
			errors++;
#ifdef CONFIG_DEBUG_INTERPRETER
			continue;
#else
			return -1;
#endif
		}

		if (*state == 0) {
#ifdef CONFIG_DEBUG_INTERPRETER
                        printk("pushed %" FMT_CELL_x " to stack\n\n", num);
#endif
			PUSH(num);
		} else {
#ifdef CONFIG_DEBUG_INTERPRETER
                        printk("writing lit, %" FMT_CELL_x " to dict\n\n", num);
#endif
			writecell(LIT);	/* lit */
			writecell(num);
		}
	}

	fclose(f);
	cursrc--;

	return 0;
}

static int build_dictionary(void)
{
	ucell lfa = 0;
	unsigned int i;

	/* we need a temporary place for latest outside the dictionary */
	latest = &lfa;

	/* starting a new dictionary: clear dicthead */
	dicthead = 0;

#ifdef CONFIG_DEBUG_DICTIONARY
	printk("building dictionary, %d primitives.\nbuilt words:",
	       sizeof(wordnames) / sizeof(void *));
#endif

	for (i = 0; i < sizeof(wordnames) / sizeof(void *); i++) {
		if (strlen(wordnames[i]) != 0) {
			fcreate((char *) wordnames[i], i);
#ifdef CONFIG_DEBUG_DICTIONARY
			printk(" %s", wordnames[i]);
#endif
		}
	}
#ifdef CONFIG_DEBUG_DICTIONARY
	printk(".\n");
#endif

	/* get last/latest and state */
	state = buildvariable("state", 0);
	last = buildvariable("forth-last", 0);
	latest = buildvariable("latest", 0);

	*latest = target_ucell(pointer2cell(latest)-2*sizeof(cell));

	base=buildvariable("base", 10);

	buildconstant("/c", sizeof(u8));
	buildconstant("/w", sizeof(u16));
	buildconstant("/l", sizeof(u32));
	buildconstant("/n", sizeof(ucell));
	buildconstant("/x", sizeof(u64));

	reveal();
        if (verbose) {
                printk("Dictionary initialization finished.\n");
        }
	return 0;
}

/*
 * functions used by primitives
 */

int availchar(void)
{
	int tmp;
	if( cursrc < 1 ) {
		interruptforth |= FORTH_INTSTAT_STOP;
		/* return -1 in order to exit the loop in key() */
		return -1;
	}

	tmp = getc( srcfiles[cursrc-1] );
	if (tmp != EOF) {
		ungetc(tmp, srcfiles[cursrc-1]);
		return -1;
	}

	fclose(srcfiles[--cursrc]);

	return availchar();
}

int get_inputbyte( void )
{
	int tmp;

	if( cursrc < 1 ) {
		interruptforth |= FORTH_INTSTAT_STOP;
		return 0;
	}

	tmp = getc( srcfiles[cursrc-1] );

	/* Update current line number */
	if (tmp == '\n') {
		srclines[cursrc - 1]++;
	}

	if (tmp != EOF) {
		return tmp;
	}

	fclose(srcfiles[--cursrc]);

	return get_inputbyte();
}

void put_outputbyte( int c )
{
	if (console)
		fputc(c, console);
}

/*
 *  segmentation fault handler. linux specific?
 */

static void
segv_handler(int signo __attribute__ ((unused)),
	     siginfo_t * si, void *context __attribute__ ((unused)))
{
	static int count = 0;
	ucell addr = 0xdeadbeef;

	if (count) {
		printk("Died while dumping forth dictionary core.\n");
		goto out;
	}

	count++;

	if (PC >= pointer2cell(dict) && PC <= pointer2cell(dict) + dicthead)
		addr = read_cell(cell2pointer(PC));

	printk("panic: segmentation violation at %p\n", (char *)si->si_addr);
	printk("dict=%p here=%p(dict+0x%" FMT_CELL_x ") pc=0x%" FMT_CELL_x "(dict+0x%" FMT_CELL_x ")\n",
	       dict, dict + dicthead, dicthead, PC, PC - pointer2cell(dict));
	printk("dstackcnt=%d rstackcnt=%d instruction=%" FMT_CELL_x "\n",
	       dstackcnt, rstackcnt, addr);

	printdstack();
	printrstack();

	printk("Writing dictionary core file\n");
	write_dictionary("forth.dict.core");

      out:
	exit(1);
}

/*
 * allocate memory and prepare engine for memory management.
 */

static void init_memory(void)
{
	memset(memory, 0, MEMORY_SIZE);

	/* we push start and end of memory to the stack
	 * so that it can be used by the forth word QUIT
	 * to initialize the memory allocator.
	 * Add a cell to the start address so we don't end
	 * up with a start address of zero during bootstrap
	 */

	PUSH(pointer2cell(memory)+sizeof(cell));
	PUSH(pointer2cell(memory) + MEMORY_SIZE-1);
}


void
include_file( const char *name )
{
	FILE *file;

	if( cursrc >= sizeof(srcfiles)/sizeof(srcfiles[0]) ) {
		printk("\npanic: Maximum include depth reached!\n");
		exit(1);
	}

	file = fopen_include( name );
	if( !file ) {
		printk("\npanic: Failed opening file '%s'\n", name );
		exit(1);
	}
}


void
encode_file( const char *name )
{
	FILE *file = fopen_include(name);
	int size;

	if( !file ) {
		printk("\npanic: Can't open '%s'\n", name );
		exit(1);
	}
	fseek( file, 0, SEEK_END );
	size = ftell( file );
	fseek( file, 0, SEEK_SET );

        if (verbose) {
                printk("\nEncoding %s [%d bytes]\n", name, size );
        }
	fread( dict + dicthead, size, 1, file );
	PUSH( pointer2cell(dict + dicthead) );
	PUSH( size );
	dicthead += size;
	paddict(sizeof(cell));
}


static void run_dictionary(char *basedict, char *confile)
{
	if(!basedict)
		return;

	read_dictionary(basedict);
	PC = (ucell)findword("initialize");

	if (!PC) {
		if (verbose) {
			printk("Unable to find initialize word in dictionary %s; ignoring\n", basedict);
		}
		return;
	}

	if(!srcfiles[0]) {
		cursrc = 1;
		srcfiles[cursrc-1] = stdin;
	}

	dstackcnt=0;
	rstackcnt=0;

	init_memory();
	if (verbose)
		printk("Jumping to dictionary %s...\n", basedict);

	/* If a console file has been specified, open it */
	if (confile)
		console = fopen(confile, "w");

	srcbasedict = basedict;	

	enterforth((xt_t)PC);

	/* Close the console file */
	if (console)
		fclose(console);
}

static void new_dictionary(const char *source)
{
	build_dictionary();

	interpret_source((char *)source);

        if (verbose || errors > 0) {
                printk("interpretion finished. %d errors occured.\n",
                       errors);
        }
}

/*
 * main loop
 */

#define BANNER	"OpenBIOS bootstrap kernel. (C) 2003-2006 Patrick Mauritz, Stefan Reinauer\n"\
		"This software comes with absolutely no warranty. "\
		"All rights reserved.\n\n"

#ifdef __GLIBC__
#define USAGE   "Usage: %s [options] [dictionary file|source file]\n\n" \
		"   -h|--help		show this help\n"		\
		"   -V|--version	print version and exit\n"	\
		"   -v|--verbose        print debugging information\n"	\
		"   -I|--include dir	add dir to include path\n"	\
		"   -d|--source-dictionary bootstrap.dict\n"		\
		"			use this dictionary as base\n"	\
		"   -D|--target-dictionary output.dict\n"		\
		"			write to output.dict\n"		\
		"   -c|--console output.log\n"		\
		"			write kernel console output to log file\n"	\
		"   -s|--segfault	install segfault handler\n"     \
                "   -M|--dependency-dump file\n"                         \
                "                       dump dependencies in Makefile format\n\n" \
                "   -x|--hexdump        output format is C language hex dump\n"
#else
#define USAGE   "Usage: %s [options] [dictionary file|source file]\n\n" \
		"   -h		show this help\n"		\
		"   -V		print version and exit\n"	\
		"   -v		print debugging information\n"	\
		"   -I		add dir to include path\n"	\
		"   -d bootstrap.dict\n"			\
		"		use this dictionary as base\n"	\
		"   -D output.dict\n"				\
		"		write to output.dict\n"		\
		"   -c output.log\n"		\
		"		write kernel console output to log file\n"	\
		"   -s		install segfault handler\n\n"   \
                "   -M file     dump dependencies in Makefile format\n\n" \
                "   -x          output format is C language hex dump\n"
#endif

int main(int argc, char *argv[])
{
	struct sigaction sa;

	unsigned char *ressources=NULL; /* All memory used by us */
        const char *dictname = NULL;
	char *basedict = NULL;
	char *consolefile = NULL;
        char *depfilename = NULL;

	unsigned char *bootstrapdict[2];
        int c, cnt, hexdump = 0;

        const char *optstring = "VvhsI:d:D:c:M:x?";

	while (1) {
#ifdef __GLIBC__
		int option_index = 0;
		static struct option long_options[] = {
			{"version", 0, NULL, 'V'},
			{"verbose", 0, NULL, 'v'},
			{"help", 0, NULL, 'h'},
			{"segfault", 0, NULL, 's'},
			{"include", 1, NULL, 'I'},
			{"source-dictionary", 1, NULL, 'd'},
			{"target-dictionary", 1, NULL, 'D'},
			{"console", 1, NULL, 'c'},
                        {"dependency-dump", 1, NULL, 'M'},
                        {"hexdump", 0, NULL, 'x'},
		};

		/*
		 * option handling
		 */

		c = getopt_long(argc, argv, optstring, long_options,
				&option_index);
#else
		c = getopt(argc, argv, optstring);
#endif
		if (c == -1)
			break;

		switch (c) {
		case 'V':
                        printk("Version " OPENBIOS_VERSION_STR "\n");
			return 0;
		case 'h':
		case '?':
                        printk("Version " OPENBIOS_VERSION_STR "\n" USAGE,
                               argv[0]);
			return 0;
		case 'v':
			verbose = 1;
			break;
		case 's':
			segfault = 1;
			break;
		case 'I':
#ifdef CONFIG_DEBUG_INTERPRETER
			printk("adding '%s' to include path\n", optarg);
#endif
			add_includepath(optarg);
			break;
		case 'd':
			if (!basedict) {
				basedict = optarg;
			}
			break;
		case 'D':
			if(!dictname) {
				dictname = optarg;
			}
			break;
		case 'c':
			if (!consolefile) {
				consolefile = optarg;
			}
			break;
                case 'M':
                        if (!depfilename) {
                                depfilename = optarg;
                        }
                        break;
                case 'x':
                        hexdump = 1;
                        break;
		default:
			return 1;
		}
	}

        if (!dictname) {
            dictname = "bootstrap.dict";
        }
        if (verbose) {
                printk(BANNER);
                printk("Using source dictionary '%s'\n", basedict);
                printk("Dumping final dictionary to '%s'\n", dictname);
                printk("Dumping dependencies to '%s'\n", depfilename);
        }

        if (argc < optind) {
		printk(USAGE, argv[0]);
		return 1;
	}

        if (depfilename) {
            depfile = fopen(depfilename, "w");
            if (!depfile) {
                printk("panic: can't write to dependency file '%s'.\n",
                       depfilename);
                exit(1);
            }
            fprintf(depfile, "%s:", dictname);
        }

	/*
	 * Get all required resources
	 */


	ressources = malloc(MEMORY_SIZE + (2 * DICTIONARY_SIZE) + TRAMPOLINE_SIZE);
	if (!ressources) {
		printk("panic: not enough memory on host system.\n");
		return 1;
	}

#ifdef NATIVE_BITWIDTH_SMALLER_THAN_HOST_BITWIDTH
	base_address=(unsigned long)ressources;
#endif

	memory = (ucell *)ressources;

	bootstrapdict[0] = ressources + MEMORY_SIZE;
	bootstrapdict[1] = ressources + MEMORY_SIZE + DICTIONARY_SIZE;
	trampoline = (ucell *)(ressources + MEMORY_SIZE + DICTIONARY_SIZE + DICTIONARY_SIZE);

#ifdef CONFIG_DEBUG_INTERPRETER
	printf("memory: %p\n",memory);
	printf("dict1: %p\n",bootstrapdict[0]);
	printf("dict2: %p\n",bootstrapdict[1]);
	printf("trampoline: %p\n",trampoline);
	printf("size=%d, trampoline_size=%d\n",MEMORY_SIZE + (2 *
				DICTIONARY_SIZE) + TRAMPOLINE_SIZE,
			TRAMPOLINE_SIZE);
#endif

	if (trampoline == NULL) {
		/* We're using side effects which is to some extent nasty */
		printf("WARNING: no trampoline!\n");
	} else {
		init_trampoline(trampoline);
	}

	if (!segfault) {
		if (verbose)
			printk("Installing SIGSEGV handler...");

		sa.sa_sigaction = segv_handler;
		sigemptyset(&sa.sa_mask);
		sa.sa_flags = SA_SIGINFO | SA_NODEFER;
                sigaction(SIGSEGV, &sa, NULL);

		if (verbose)
			printk("done.\n");
	}

	/*
	 * Now do the real work
	 */

	for (cnt=0; cnt<2; cnt++) {
                if (verbose) {
                        printk("Compiling dictionary %d/%d\n", cnt+1, 2);
                }
		dict=bootstrapdict[cnt];
		if(!basedict) {
			new_dictionary(argv[optind]);
		} else {
			for (c=argc-1; c>=optind; c--)
				include_file(argv[c]);

			run_dictionary(basedict, consolefile);
		}
                if (depfile) {
                        fprintf(depfile, "\n");
                        fclose(depfile);
                        depfile = NULL;
                }
		if(errors)
			break;
	}

#ifndef CONFIG_DEBUG_INTERPRETER
	if (errors)
		printk("dictionary not dumped to file.\n");
	else
#endif
	{
		relocation_table( bootstrapdict[0], bootstrapdict[1], dicthead);
                if (hexdump) {
                    write_dictionary_hex(dictname);
                } else {
                    write_dictionary(dictname);
                }
	}

	free(ressources);

        if (errors)
            return 1;
        else
            return 0;
}
