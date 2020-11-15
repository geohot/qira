/* tag: C implementation of all forth primitives,
 * internal words, inner interpreter and such
 *
 * Copyright (C) 2003 Patrick Mauritz, Stefan Reinauer
 *
 * See the file "COPYING" for further information about
 * the copyright and warranty status of this work.
 */

#include "config.h"
#include "sysinclude.h"
#include "kernel/stack.h"
#include "kernel/kernel.h"
#include "dict.h"

/*
 * cross platform abstraction
 */

#include "cross.h"

#ifndef FCOMPILER
#include "libc/vsprintf.h"
#else
#include <stdarg.h>
#endif

/*
 * execution works as follows:
 *  - PC is pushed on return stack
 *  - PC is set to new CFA
 *  - address pointed by CFA is executed by CPU
 */

typedef void forth_word(void);

static forth_word * const words[];
ucell PC;
volatile int interruptforth = 0;

#define DEBUG_MODE_NONE 0
#define DEBUG_MODE_STEP 1
#define DEBUG_MODE_TRACE 2
#define DEBUG_MODE_STEPUP 3

#define DEBUG_BANNER "\nStepper keys: <space>/<enter> Up Down Trace Rstack Forth\n"

/* Empty linked list of debug xts */
struct debug_xt {
    ucell xt_docol;
    ucell xt_semis;
    int mode;
    struct debug_xt *next;
};

static struct debug_xt debug_xt_eol = { (ucell)0, (ucell)0, 0, NULL};
static struct debug_xt *debug_xt_list = &debug_xt_eol;

/* Static buffer for xt name */
char xtname[MAXNFALEN];

#ifndef FCOMPILER
/* instead of pointing to an explicit 0 variable we
 * point behind the pointer.
 */
static ucell t[] = { 0, 0, 0, 0 };
static ucell *trampoline = t;

/*
 * Code Field Address (CFA) definitions (DOCOL and the like)
 */

void forth_init(void)
{
    init_trampoline(trampoline);
}
#endif

#ifndef CONFIG_DEBUG_INTERPRETER
#define dbg_interp_printk( a... )       do { } while(0)
#else
#define dbg_interp_printk( a... )       printk( a )
#endif

#ifndef CONFIG_DEBUG_INTERNAL
#define dbg_internal_printk( a... )     do { } while(0)
#else
#define dbg_internal_printk( a... )     printk( a )
#endif


void init_trampoline(ucell *tramp)
{
    tramp[0] = DOCOL;
    tramp[1] = 0;
    tramp[2] = target_ucell(pointer2cell(tramp) + 3 * sizeof(ucell));
    tramp[3] = 0;
}

static inline void processxt(ucell xt)
{
    void (*tokenp) (void);

    dbg_interp_printk("processxt: pc=%x, xt=%x\n", PC, xt);
    tokenp = words[xt];
    tokenp();
}

static void docol(void)
{                               /* DOCOL */
    PUSHR(PC);
    PC = read_ucell(cell2pointer(PC));

    dbg_interp_printk("docol: %s\n", cell2pointer( lfa2nfa(PC - sizeof(cell)) ));
}

static void semis(void)
{
    PC = POPR();
}

static inline void next(void)
{
    PC += sizeof(ucell);

    dbg_interp_printk("next: PC is now %x\n", PC);
    processxt(read_ucell(cell2pointer(read_ucell(cell2pointer(PC)))));
}

static inline void next_dbg(void);

int enterforth(xt_t xt)
{
    ucell *_cfa = (ucell*)cell2pointer(xt);
    cell tmp;

    if (read_ucell(_cfa) != DOCOL) {
        trampoline[1] = target_ucell(xt);
        _cfa = trampoline;
    }

    if (rstackcnt < 0) {
        rstackcnt = 0;
    }

    tmp = rstackcnt;
    interruptforth = FORTH_INTSTAT_CLR;

    PUSHR(PC);
    PC = pointer2cell(_cfa);

    while (rstackcnt > tmp && !(interruptforth & FORTH_INTSTAT_STOP)) {
        if (debug_xt_list->next == NULL) {
            while (rstackcnt > tmp && !interruptforth) {
                dbg_interp_printk("enterforth: NEXT\n");
                next();
            }
        } else {
            while (rstackcnt > tmp && !interruptforth) {
                dbg_interp_printk("enterforth: NEXT_DBG\n");
                next_dbg();
            }
        }

        /* Always clear the debug mode change flag */
        interruptforth = interruptforth & (~FORTH_INTSTAT_DBG);
    }

#if 0
    /* return true if we took an exception. The caller should normally
     * handle exceptions by returning immediately since the throw
     * is supposed to abort the execution of this C-code too.
     */

    if (rstackcnt != tmp) {
        printk("EXCEPTION DETECTED!\n");
    }
#endif
    return rstackcnt != tmp;
}

/* called inline thus a slightly different behaviour */
static void lit(void)
{                               /* LIT */
    PC += sizeof(cell);
    PUSH(read_ucell(cell2pointer(PC)));
    dbg_interp_printk("lit: %x\n", read_ucell(cell2pointer(PC)));
}

static void docon(void)
{                               /* DOCON */
    ucell tmp = read_ucell(cell2pointer(read_ucell(cell2pointer(PC)) + sizeof(ucell)));
    PUSH(tmp);
    dbg_interp_printk("docon: PC=%x, value=%x\n", PC, tmp);
}

static void dovar(void)
{                               /* DOVAR */
    ucell tmp = read_ucell(cell2pointer(PC)) + sizeof(ucell);
    PUSH(tmp);              /* returns address to variable */
    dbg_interp_printk("dovar: PC: %x, %x\n", PC, tmp);
}

static void dobranch(void)
{                               /* unconditional branch */
    PC += sizeof(cell);
    PC += read_cell(cell2pointer(PC));
}

static void docbranch(void)
{                               /* conditional branch */
    PC += sizeof(cell);
    if (POP()) {
        dbg_internal_printk("  ?branch: end loop\n");
    } else {
        dbg_internal_printk("  ?branch: follow branch\n");
        PC += read_cell(cell2pointer(PC));
    }
}


static void execute(void)
{                               /* EXECUTE */
    ucell address = POP();
    dbg_interp_printk("execute: %x\n", address);

    PUSHR(PC);
    trampoline[1] = target_ucell(address);
    PC = pointer2cell(trampoline);
}

/*
 * call ( ... function-ptr -- ??? )
 */
static void call(void)
{
#ifdef FCOMPILER
    printk("Sorry. Usage of Forth2C binding is forbidden during bootstrap.\n");
    exit(1);
#else
    void (*funcptr) (void);
    funcptr=(void *)cell2pointer(POP());
    dbg_interp_printk("call: %x", funcptr);
    funcptr();
#endif
}

/*
 * sys-debug ( errno -- )
 */

static void sysdebug(void)
{
#ifdef FCOMPILER
    cell errorno=POP();
    exception(errorno);
#else
    (void) POP();
#endif
}

static void dodoes(void)
{                               /* DODOES */
    ucell data = read_ucell(cell2pointer(PC)) + (2 * sizeof(ucell));
    ucell word = read_ucell(cell2pointer(read_ucell(cell2pointer(PC)) + sizeof(ucell)));

    dbg_interp_printk("DODOES data=%x word=%x\n", data, word);

    PUSH(data);
    PUSH(word);

    execute();
}

static void dodefer(void)
{
    docol();
}

static void dodo(void)
{
    cell startval, endval;
    startval = POP();
    endval = POP();

    PUSHR(endval);
    PUSHR(startval);
}

static void doisdo(void)
{
    cell startval, endval, offset;

    startval = POP();
    endval = POP();

    PC += sizeof(cell);

    if (startval == endval) {
        offset = read_cell(cell2pointer(PC));
        PC += offset;
    } else {
        PUSHR(endval);
        PUSHR(startval);
    }
}

static void doloop(void)
{
    cell offset, startval, endval;

    startval = POPR() + 1;
    endval = POPR();

    PC += sizeof(cell);

    if (startval < endval) {
        offset = read_cell(cell2pointer(PC));
        PC += offset;
        PUSHR(endval);
        PUSHR(startval);
    }

}

static void doplusloop(void)
{
    ucell high, low;
    cell increment, startval, endval, offset;

    increment = POP();

    startval = POPR();
    endval = POPR();

    low = (ucell) startval;
    startval += increment;

    PC += sizeof(cell);

    if (increment >= 0) {
        high = (ucell) startval;
    } else {
        high = low;
        low = (ucell) startval;
    }

    if (endval - (low + 1) >= high - low) {
        offset = read_cell(cell2pointer(PC));
        PC += offset;

        PUSHR(endval);
        PUSHR(startval);
    }
}

/*
 *  instance handling CFAs
 */
#ifndef FCOMPILER
static ucell get_myself(void)
{
    static ucell *myselfptr = NULL;
    if (myselfptr == NULL) {
        myselfptr = (ucell*)cell2pointer(findword("my-self")) + 1;
    }
    ucell *myself = (ucell*)cell2pointer(*myselfptr);
    return (myself != NULL) ? *myself : 0;
}

static void doivar(void)
{
    ucell r, *p = (ucell *)(*(ucell *) cell2pointer(PC) + sizeof(ucell));
    ucell ibase = get_myself();

    dbg_interp_printk("ivar, offset: %d size: %d (ibase %d)\n", p[0], p[1], ibase );

    r = ibase ? ibase + p[0] : pointer2cell(&p[2]);
    PUSH( r );
}

static void doival(void)
{
    ucell r, *p = (ucell *)(*(ucell *) cell2pointer(PC) + sizeof(ucell));
    ucell ibase = get_myself();

    dbg_interp_printk("ivar, offset: %d size: %d\n", p[0], p[1] );

    r = ibase ? ibase + p[0] : pointer2cell(&p[2]);
    PUSH( *(ucell *)cell2pointer(r) );
}

static void doidefer(void)
{
    ucell *p = (ucell *)(*(ucell *) cell2pointer(PC) + sizeof(ucell));
    ucell ibase = get_myself();

    dbg_interp_printk("doidefer, offset: %d size: %d\n", p[0], p[1] );

    PUSHR(PC);
    PC = ibase ? ibase + p[0] : pointer2cell(&p[2]);
    PC -= sizeof(ucell);
}
#else
static void noinstances(void)
{
    printk("Opening devices is not supported during bootstrap. Sorry.\n");
    exit(1);
}
#define doivar   noinstances
#define doival   noinstances
#define doidefer noinstances
#endif

/*
 * $include / $encode-file
 */
#ifdef FCOMPILER
static void
string_relay(void (*func)(const char *))
{
    int len = POP();
    char *name, *p = (char*)cell2pointer(POP());
    name = malloc(len + 1);
    memcpy(name, p, len);
    name[len] = 0;
    (*func)(name);
    free(name);
}
#else
#define string_relay(dummy) do { DROP(); DROP(); } while(0)
#endif

static void
do_include(void)
{
    string_relay(&include_file);
}

static void
do_encode_file( void )
{
    string_relay(&encode_file);
}

/*
 * Debug support functions
 */

static
int printf_console(const char *fmt, ...)
{
    cell tmp;

    char buf[512];
    va_list args;
    int i;

    va_start(args, fmt);
    i = vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    /* Push to the Forth interpreter for console output */
    tmp = rstackcnt;

    PUSH(pointer2cell(buf));
    PUSH((int)strlen(buf));
    trampoline[1] = findword("type");

    PUSHR(PC);
    PC = pointer2cell(trampoline);

    while (rstackcnt > tmp) {
        dbg_interp_printk("printf_console: NEXT\n");
        next();
    }

    return i;
}

static
int getchar_console(void)
{
    cell tmp;

    /* Push to the Forth interpreter for console output */
    tmp = rstackcnt;

    trampoline[1] = findword("key");

    PUSHR(PC);
    PC = pointer2cell(trampoline);

    while (rstackcnt > tmp) {
        dbg_interp_printk("getchar_console: NEXT\n");
        next();
    }

    return POP();
}

static void
display_dbg_dstack(void)
{
    /* Display dstack contents between parentheses */
    int i;

    if (dstackcnt == 0) {
        printf_console(" ( Empty ) ");
        return;
    } else {
        printf_console(" ( ");
        for (i = 1; i <= dstackcnt; i++) {
            if (i != 1) {
                printf_console(" ");
            }
            printf_console("%" FMT_CELL_x, dstack[i]);
        }
        printf_console(" ) ");
    }
}

static void
display_dbg_rstack(void)
{
    /* Display rstack contents between parentheses */
    int i;

    if (rstackcnt == 0) {
        printf_console(" ( Empty ) ");
        return;
    } else {
        printf_console("\nR: ( ");
        for (i = 1; i <= rstackcnt; i++) {
            if (i != 1) {
                printf_console(" ");
            }
            printf_console("%" FMT_CELL_x, rstack[i]);
        }
        printf_console(" ) \n");
    }
}

static int
add_debug_xt(ucell xt)
{
    struct debug_xt *debug_xt_item;

    /* If the xt CFA isn't DOCOL then issue a warning and do nothing */
    if (read_ucell(cell2pointer(xt)) != DOCOL) {
        printf_console("\nprimitive words cannot be debugged\n");
        return 0;
    }

    /* If this xt is already in the list, do nothing but indicate success */
    for (debug_xt_item = debug_xt_list; debug_xt_item->next != NULL;
         debug_xt_item = debug_xt_item->next)
        if (debug_xt_item->xt_docol == xt) {
            return 1;
        }

    /* We already have the CFA (PC) indicating the starting cell of
       the word, however we also need the ending cell too (we cannot
       rely on the rstack as it can be arbitrarily changed by a forth
       word). Hence the use of findsemis() */

    /* Otherwise add to the head of the linked list */
    debug_xt_item = malloc(sizeof(struct debug_xt));
    debug_xt_item->xt_docol = xt;
    debug_xt_item->xt_semis = findsemis(xt);
    debug_xt_item->mode = DEBUG_MODE_NONE;
    debug_xt_item->next = debug_xt_list;
    debug_xt_list = debug_xt_item;

    /* Indicate debug mode change */
    interruptforth |= FORTH_INTSTAT_DBG;

    /* Success */
    return 1;
}

static void
del_debug_xt(ucell xt)
{
    struct debug_xt *debug_xt_item, *tmp_xt_item;

    /* Handle the case where the xt is at the head of the list */
    if (debug_xt_list->xt_docol == xt) {
        tmp_xt_item = debug_xt_list;
        debug_xt_list = debug_xt_list->next;
        free(tmp_xt_item);

        return;
    }

    /* Otherwise find this xt in the linked list and remove it */
    for (debug_xt_item = debug_xt_list; debug_xt_item->next != NULL;
         debug_xt_item = debug_xt_item->next) {
        if (debug_xt_item->next->xt_docol == xt) {
            tmp_xt_item = debug_xt_item->next;
            debug_xt_item->next = debug_xt_item->next->next;
            free(tmp_xt_item);
        }
    }

    /* If the list is now empty, indicate debug mode change */
    if (debug_xt_list->next == NULL) {
        interruptforth |= FORTH_INTSTAT_DBG;
    }
}

static void
do_source_dbg(struct debug_xt *debug_xt_item)
{
    /* Forth source debugger implementation */
    char k, done = 0;

    /* Display current dstack */
    display_dbg_dstack();
    printf_console("\n");

    fstrncpy(xtname, lfa2nfa(read_ucell(cell2pointer(PC)) - sizeof(cell)), MAXNFALEN);
    printf_console("%p: %s ", cell2pointer(PC), xtname);

    /* If in trace mode, we just carry on */
    if (debug_xt_item->mode == DEBUG_MODE_TRACE) {
        return;
    }

    /* Otherwise in step mode, prompt for a keypress */
    k = getchar_console();

    /* Only proceed if done is true */
    while (!done) {
        switch (k) {

        case ' ':
        case '\n':
            /* Perform a single step */
            done = 1;
            break;

        case 'u':
        case 'U':
            /* Up - unmark current word for debug, mark its caller for
             * debugging and finish executing current word */

            /* Since this word could alter the rstack during its execution,
             * we only know the caller when (semis) is called for this xt.
             * Hence we mark the xt as a special DEBUG_MODE_STEPUP which
             * means we run as normal, but schedule the xt for deletion
             * at its corresponding (semis) word when we know the rstack
             * will be set to its final parent value */
            debug_xt_item->mode = DEBUG_MODE_STEPUP;
            done = 1;
            break;

        case 'd':
        case 'D':
            /* Down - mark current word for debug and step into it */
            done = add_debug_xt(read_ucell(cell2pointer(PC)));
            if (!done) {
                k = getchar_console();
            }
            break;

        case 't':
        case 'T':
            /* Trace mode */
            debug_xt_item->mode = DEBUG_MODE_TRACE;
            done = 1;
            break;

        case 'r':
        case 'R':
            /* Display rstack */
            display_dbg_rstack();
            done = 0;
            k = getchar_console();
            break;

        case 'f':
        case 'F':
            /* Start subordinate Forth interpreter */
            PUSHR(PC - sizeof(cell));
            PC = findword("outer-interpreter") + sizeof(ucell);

            /* Save rstack position for when we return */
            dbgrstackcnt = rstackcnt;
            done = 1;
            break;

        default:
            /* Display debug banner */
            printf_console(DEBUG_BANNER);
            k = getchar_console();
        }
    }
}

static void docol_dbg(void)
{                               /* DOCOL */
    struct debug_xt *debug_xt_item;

    PUSHR(PC);
    PC = read_ucell(cell2pointer(PC));

    /* If current xt is in our debug xt list, display word name */
    debug_xt_item = debug_xt_list;
    while (debug_xt_item->next) {
        if (debug_xt_item->xt_docol == PC) {
            fstrncpy(xtname, lfa2nfa(PC - sizeof(cell)), MAXNFALEN);
            printf_console("\n: %s ", xtname);

            /* Step mode is the default */
            debug_xt_item->mode = DEBUG_MODE_STEP;
        }

        debug_xt_item = debug_xt_item->next;
    }

    dbg_interp_printk("docol_dbg: %s\n", cell2pointer(lfa2nfa(PC - sizeof(cell))));
}

static void semis_dbg(void)
{
    struct debug_xt *debug_xt_item, *debug_xt_up = NULL;

    /* If current semis is in our debug xt list, disable debug mode */
    debug_xt_item = debug_xt_list;
    while (debug_xt_item->next) {
        if (debug_xt_item->xt_semis == PC) {
            if (debug_xt_item->mode != DEBUG_MODE_STEPUP) {
                /* Handle the normal case */
                fstrncpy(xtname, lfa2nfa(debug_xt_item->xt_docol - sizeof(cell)), MAXNFALEN);
                printf_console("\n[ Finished %s ] ", xtname);

                /* Reset to step mode in case we were in trace mode */
                debug_xt_item->mode = DEBUG_MODE_STEP;
            } else {
                /* This word requires execution of the debugger "Up"
                 * semantics. However we can't do this here since we
                 * are iterating through the debug list, and we need
                 * to change it. So we do it afterwards.
                 */
                debug_xt_up = debug_xt_item;
            }
        }

        debug_xt_item = debug_xt_item->next;
    }

    /* Execute debugger "Up" semantics if required */
    if (debug_xt_up) {
        /* Only add the parent word if it is not within the trampoline */
        if (rstack[rstackcnt] != (cell)pointer2cell(&trampoline[1])) {
            del_debug_xt(debug_xt_up->xt_docol);
            add_debug_xt(findxtfromcell(rstack[rstackcnt]));

            fstrncpy(xtname, lfa2nfa(findxtfromcell(rstack[rstackcnt]) - sizeof(cell)), MAXNFALEN);
            printf_console("\n[ Up to %s ] ", xtname);
        } else {
            fstrncpy(xtname, lfa2nfa(findxtfromcell(debug_xt_up->xt_docol) - sizeof(cell)), MAXNFALEN);
            printf_console("\n[ Finished %s (Unable to go up, hit trampoline) ] ", xtname);

            del_debug_xt(debug_xt_up->xt_docol);
        }

        debug_xt_up = NULL;
    }

    PC = POPR();
}

static inline void next_dbg(void)
{
    struct debug_xt *debug_xt_item;
    void (*tokenp) (void);

    PC += sizeof(ucell);

    /* If the PC lies within a debug range, run the source debugger */
    debug_xt_item = debug_xt_list;
    while (debug_xt_item->next) {
        if (PC >= debug_xt_item->xt_docol && PC <= debug_xt_item->xt_semis &&
            debug_xt_item->mode != DEBUG_MODE_STEPUP) {
            do_source_dbg(debug_xt_item);
        }

        debug_xt_item = debug_xt_item->next;
    }

    dbg_interp_printk("next_dbg: PC is now %x\n", PC);

    /* Intercept DOCOL and SEMIS and redirect to debug versions */
    if (read_ucell(cell2pointer(read_ucell(cell2pointer(PC)))) == DOCOL) {
        tokenp = docol_dbg;
        tokenp();
    } else if (read_ucell(cell2pointer(read_ucell(cell2pointer(PC)))) == DOSEMIS) {
        tokenp = semis_dbg;
        tokenp();
    } else {
        /* Otherwise process as normal */
        processxt(read_ucell(cell2pointer(read_ucell(cell2pointer(PC)))));
    }
}

static void
do_debug_xt(void)
{
    ucell xt = POP();

    /* Add to the debug list */
    if (add_debug_xt(xt)) {
        /* Display debug banner */
        printf_console(DEBUG_BANNER);

        /* Indicate change to debug mode */
        interruptforth |= FORTH_INTSTAT_DBG;
    }
}

static void
do_debug_off(void)
{
    /* Empty the debug xt linked list */
    while (debug_xt_list->next != NULL) {
        del_debug_xt(debug_xt_list->xt_docol);
    }
}

/*
 * Forth primitives needed to set up
 * all the words described in IEEE1275-1994.
 */

/*
 *  dup         ( x -- x x )
 */

static void fdup(void)
{
	const cell tmp = GETTOS();
	PUSH(tmp);
}


/*
 *  2dup        ( x1 x2 -- x1 x2 x1 x2 )
 */

static void twodup(void)
{
	cell tmp = GETITEM(1);
	PUSH(tmp);
	tmp = GETITEM(1);
	PUSH(tmp);
}


/*
 *  ?dup        ( x -- 0 | x x )
 */

static void isdup(void)
{
	const cell tmp = GETTOS();
	if (tmp)
		PUSH(tmp);
}


/*
 *  over        ( x y -- x y x )
 */

static void over(void)
{
	const cell tmp = GETITEM(1);
	PUSH(tmp);
}


/*
 *  2over ( x1 x2 x3 x4 -- x1 x2 x3 x4 x1 x2 )
 */

static void twoover(void)
{
	const cell tmp = GETITEM(3);
	const cell tmp2 = GETITEM(2);
	PUSH(tmp);
	PUSH(tmp2);
}

/*
 *  pick        ( xu ... x1 x0 u -- xu ... x1 x0 xu )
 */

static void pick(void)
{
	const cell u = POP();
	if (dstackcnt >= u) {
		ucell tmp = dstack[dstackcnt - u];
		PUSH(tmp);
	} else {
		/* underrun */
	}
}


/*
 *  drop        ( x --  )
 */

static void drop(void)
{
	POP();
}

/*
 *  2drop       ( x1 x2 --  )
 */

static void twodrop(void)
{
	POP();
	POP();
}


/*
 *  nip         ( x1 x2 -- x2 )
 */

static void nip(void)
{
	const cell tmp = POP();
	POP();
	PUSH(tmp);
}


/*
 *  roll        ( xu ... x1 x0 u -- xu-1... x1 x0 xu )
 */

static void roll(void)
{
	const cell u = POP();
	if (dstackcnt >= u) {
		int i;
		const cell xu = dstack[dstackcnt - u];
		for (i = dstackcnt - u; i < dstackcnt; i++) {
			dstack[i] = dstack[i + 1];
		}
		dstack[dstackcnt] = xu;
	} else {
		/* Stack underrun */
	}
}


/*
 *  rot         ( x1 x2 x3 -- x2 x3 x1 )
 */

static void rot(void)
{
	const cell tmp = POP();
	const cell tmp2 = POP();
	const cell tmp3 = POP();
	PUSH(tmp2);
	PUSH(tmp);
	PUSH(tmp3);
}


/*
 *  -rot        ( x1 x2 x3 -- x3 x1 x2 )
 */

static void minusrot(void)
{
	const cell tmp = POP();
	const cell tmp2 = POP();
	const cell tmp3 = POP();
	PUSH(tmp);
	PUSH(tmp3);
	PUSH(tmp2);
}


/*
 *  swap        ( x1 x2 -- x2 x1 )
 */

static void swap(void)
{
	const cell tmp = POP();
	const cell tmp2 = POP();
	PUSH(tmp);
	PUSH(tmp2);
}


/*
 *  2swap       ( x1 x2 x3 x4 -- x3 x4 x1 x2 )
 */

static void twoswap(void)
{
	const cell tmp = POP();
	const cell tmp2 = POP();
	const cell tmp3 = POP();
	const cell tmp4 = POP();
	PUSH(tmp2);
	PUSH(tmp);
	PUSH(tmp4);
	PUSH(tmp3);
}


/*
 *  >r          ( x -- ) (R: -- x )
 */

static void tor(void)
{
	ucell tmp = POP();
#ifdef CONFIG_DEBUG_RSTACK
	printk("  >R: %x\n", tmp);
#endif
	PUSHR(tmp);
}


/*
 *  r>          ( -- x ) (R: x -- )
 */

static void rto(void)
{
	ucell tmp = POPR();
#ifdef CONFIG_DEBUG_RSTACK
	printk("  R>: %x\n", tmp);
#endif
	PUSH(tmp);
}


/*
 *  r@          ( -- x ) (R: x -- x )
 */

static void rfetch(void)
{
	PUSH(GETTORS());
}


/*
 *  depth       (  -- u )
 */

static void depth(void)
{
	const cell tmp = dstackcnt;
	PUSH(tmp);
}


/*
 *  depth!      ( ... u --  x1 x2 .. xu )
 */

static void depthwrite(void)
{
	ucell tmp = POP();
	dstackcnt = tmp;
}


/*
 *  rdepth      (  -- u )
 */

static void rdepth(void)
{
	const cell tmp = rstackcnt;
	PUSH(tmp);
}


/*
 *  rdepth!     ( u --  ) ( R: ... -- x1 x2 .. xu )
 */

static void rdepthwrite(void)
{
	ucell tmp = POP();
	rstackcnt = tmp;
}


/*
 *  +           ( nu1 nu2 -- sum )
 */

static void plus(void)
{
	cell tmp = POP() + POP();
	PUSH(tmp);
}


/*
 *  -           ( nu1 nu2 -- diff )
 */

static void minus(void)
{
	const cell nu2 = POP();
	const cell nu1 = POP();
	PUSH(nu1 - nu2);
}


/*
 *  *           ( nu1 nu2 -- prod )
 */

static void mult(void)
{
	const cell nu2 = POP();
	const cell nu1 = POP();
	PUSH(nu1 * nu2);
}


/*
 *  u*          ( u1 u2 -- prod )
 */

static void umult(void)
{
	const ucell tmp = (ucell) POP() * (ucell) POP();
	PUSH(tmp);
}


/*
 *  mu/mod      ( n1 n2 -- rem quot.l quot.h )
 */

static void mudivmod(void)
{
	const ucell b = POP();
	const ducell a = DPOP();
#ifdef NEED_FAKE_INT128_T
        if (a.hi != 0) {
            fprintf(stderr, "mudivmod called (0x%016llx %016llx / 0x%016llx)\n",
                    a.hi, a.lo, b);
            exit(-1);
        } else {
            ducell c;

            PUSH(a.lo % b);
            c.hi = 0;
            c.lo = a.lo / b;
            DPUSH(c);
        }
#else
	PUSH(a % b);
	DPUSH(a / b);
#endif
}


/*
 *  abs         ( n -- u )
 */

static void forthabs(void)
{
	const cell tmp = GETTOS();
	if (tmp < 0) {
		POP();
		PUSH(-tmp);
	}
}


/*
 *  negate      ( n1 -- n2 )
 */

static void negate(void)
{
	const cell tmp = POP();
	PUSH(-tmp);
}


/*
 *  max         ( n1 n2 -- n1|n2 )
 */

static void max(void)
{
	const cell tmp = POP();
	const cell tmp2 = POP();
	PUSH((tmp > tmp2) ? tmp : tmp2);
}


/*
 *  min         ( n1 n2 -- n1|n2 )
 */

static void min(void)
{
	const cell tmp = POP();
	const cell tmp2 = POP();
	PUSH((tmp < tmp2) ? tmp : tmp2);
}


/*
 *  lshift      ( x1 u -- x2 )
 */

static void lshift(void)
{
	const ucell u = POP();
	const ucell x1 = POP();
	PUSH(x1 << u);
}


/*
 *  rshift      ( x1 u -- x2 )
 */

static void rshift(void)
{
	const ucell u = POP();
	const ucell x1 = POP();
	PUSH(x1 >> u);
}


/*
 *  >>a         ( x1 u -- x2 ) ??
 */

static void rshifta(void)
{
	const cell u = POP();
	const cell x1 = POP();
	PUSH(x1 >> u);
}


/*
 *  and         ( x1 x2 -- x3 )
 */

static void and(void)
{
	const cell x1 = POP();
	const cell x2 = POP();
	PUSH(x1 & x2);
}


/*
 *  or          ( x1 x2 -- x3 )
 */

static void or(void)
{
	const cell x1 = POP();
	const cell x2 = POP();
	PUSH(x1 | x2);
}


/*
 *  xor         ( x1 x2 -- x3 )
 */

static void xor(void)
{
	const cell x1 = POP();
	const cell x2 = POP();
	PUSH(x1 ^ x2);
}


/*
 *  invert      ( x1 -- x2 )
 */

static void invert(void)
{
	const cell x1 = POP();
	PUSH(x1 ^ -1);
}


/*
 *  d+          ( d1 d2 -- d.sum )
 */

static void dplus(void)
{
	const dcell d2 = DPOP();
	const dcell d1 = DPOP();
#ifdef NEED_FAKE_INT128_T
        ducell c;

        if (d1.hi != 0 || d2.hi != 0) {
            fprintf(stderr, "dplus called (0x%016llx %016llx + 0x%016llx %016llx)\n",
                    d1.hi, d1.lo, d2.hi, d2.lo);
            exit(-1);
        }
        c.hi = 0;
        c.lo = d1.lo + d2.lo;
        DPUSH(c);
#else
	DPUSH(d1 + d2);
#endif
}


/*
 *  d-          ( d1 d2 -- d.diff )
 */

static void dminus(void)
{
	const dcell d2 = DPOP();
	const dcell d1 = DPOP();
#ifdef NEED_FAKE_INT128_T
        ducell c;

        if (d1.hi != 0 || d2.hi != 0) {
            fprintf(stderr, "dminus called (0x%016llx %016llx + 0x%016llx %016llx)\n",
                    d1.hi, d1.lo, d2.hi, d2.lo);
            exit(-1);
        }
        c.hi = 0;
        c.lo = d1.lo - d2.lo;
        DPUSH(c);
#else
	DPUSH(d1 - d2);
#endif
}


/*
 *  m*          ( ?? --  )
 */

static void mmult(void)
{
	const cell u2 = POP();
	const cell u1 = POP();
#ifdef NEED_FAKE_INT128_T
        ducell c;

        if (0) { // XXX How to detect overflow?
            fprintf(stderr, "mmult called (%016llx * 0x%016llx)\n", u1, u2);
            exit(-1);
        }
        c.hi = 0;
        c.lo = u1 * u2;
        DPUSH(c);
#else
	DPUSH((dcell) u1 * u2);
#endif
}


/*
 *  um*         ( u1 u2 -- d.prod )
 */

static void ummult(void)
{
	const ucell u2 = POP();
	const ucell u1 = POP();
#ifdef NEED_FAKE_INT128_T
        ducell c;

        if (0) { // XXX How to detect overflow?
            fprintf(stderr, "ummult called (%016llx * 0x%016llx)\n", u1, u2);
            exit(-1);
        }
        c.hi = 0;
        c.lo = u1 * u2;
        DPUSH(c);
#else
	DPUSH((ducell) u1 * u2);
#endif
}


/*
 *  @           ( a-addr -- x )
 */

static void fetch(void)
{
	const ucell *aaddr = (ucell *)cell2pointer(POP());
	PUSH(read_ucell(aaddr));
}


/*
 *  c@          ( addr -- byte )
 */

static void cfetch(void)
{
	const u8 *aaddr = (u8 *)cell2pointer(POP());
	PUSH(read_byte(aaddr));
}


/*
 *  w@          ( waddr -- w )
 */

static void wfetch(void)
{
	const u16 *aaddr = (u16 *)cell2pointer(POP());
	PUSH(read_word(aaddr));
}


/*
 *  l@          ( qaddr -- quad )
 */

static void lfetch(void)
{
	const u32 *aaddr = (u32 *)cell2pointer(POP());
	PUSH(read_long(aaddr));
}


/*
 *  !           ( x a-addr -- )
 */

static void store(void)
{
	const ucell *aaddr = (ucell *)cell2pointer(POP());
	const ucell x = POP();
#ifdef CONFIG_DEBUG_INTERNAL
	printk("!: %lx : %lx -> %lx\n", aaddr, read_ucell(aaddr), x);
#endif
	write_ucell(aaddr,x);
}


/*
 *  +!          ( nu a-addr -- )
 */

static void plusstore(void)
{
	const ucell *aaddr = (ucell *)cell2pointer(POP());
	const cell nu = POP();
	write_cell(aaddr,read_cell(aaddr)+nu);
}


/*
 *  c!          ( byte addr -- )
 */

static void cstore(void)
{
	const u8 *aaddr = (u8 *)cell2pointer(POP());
	const ucell byte = POP();
#ifdef CONFIG_DEBUG_INTERNAL
	printk("c!: %x = %x\n", aaddr, byte);
#endif
	write_byte(aaddr, byte);
}


/*
 *  w!          ( w waddr -- )
 */

static void wstore(void)
{
	const u16 *aaddr = (u16 *)cell2pointer(POP());
	const u16 word = POP();
	write_word(aaddr, word);
}


/*
 *  l!          ( quad qaddr -- )
 */

static void lstore(void)
{
	const u32 *aaddr = (u32 *)cell2pointer(POP());
	const u32 longval = POP();
	write_long(aaddr, longval);
}


/*
 *  =           ( x1 x2 -- equal? )
 */

static void equals(void)
{
	cell tmp = (POP() == POP());
	PUSH(-tmp);
}


/*
 *  >           ( n1 n2 -- greater? )
 */

static void greater(void)
{
	cell tmp = ((cell) POP() < (cell) POP());
	PUSH(-tmp);
}


/*
 *  <           ( n1 n2 -- less? )
 */

static void less(void)
{
	cell tmp = ((cell) POP() > (cell) POP());
	PUSH(-tmp);
}


/*
 *  u>          ( u1 u2 -- unsigned-greater? )
 */

static void ugreater(void)
{
	cell tmp = ((ucell) POP() < (ucell) POP());
	PUSH(-tmp);
}


/*
 *  u<          ( u1 u2 -- unsigned-less? )
 */

static void uless(void)
{
	cell tmp = ((ucell) POP() > (ucell) POP());
	PUSH(-tmp);
}


/*
 *  sp@         (  -- stack-pointer )
 */

static void spfetch(void)
{
	// FIXME this can only work if the stack pointer
	// is within range.
	ucell tmp = pointer2cell(&(dstack[dstackcnt]));
	PUSH(tmp);
}


/*
 *  move        ( src-addr dest-addr len -- )
 */

static void fmove(void)
{
	ucell count = POP();
	void *dest = (void *)cell2pointer(POP());
	const void *src = (const void *)cell2pointer(POP());
	memmove(dest, src, count);
}


/*
 *  fill        ( addr len byte -- )
 */

static void ffill(void)
{
	ucell value = POP();
	ucell count = POP();
	void *src = (void *)cell2pointer(POP());
	memset(src, value, count);
}


/*
 *  unaligned-w@  ( addr -- w )
 */

static void unalignedwordread(void)
{
	const unsigned char *addr = (const unsigned char *) cell2pointer(POP());
	PUSH(unaligned_read_word(addr));
}


/*
 *  unaligned-w!  ( w addr -- )
 */

static void unalignedwordwrite(void)
{
	const unsigned char *addr = (const unsigned char *) cell2pointer(POP());
	u16 w = POP();
	unaligned_write_word(addr, w);
}


/*
 *  unaligned-l@  ( addr -- quad )
 */

static void unalignedlongread(void)
{
	const unsigned char *addr = (const unsigned char *) cell2pointer(POP());
	PUSH(unaligned_read_long(addr));
}


/*
 *  unaligned-l!  ( quad addr -- )
 */

static void unalignedlongwrite(void)
{
	unsigned char *addr = (unsigned char *) cell2pointer(POP());
	u32 l = POP();
	unaligned_write_long(addr, l);
}

/*
 *  here        (  -- dictionary-pointer )
 */

static void here(void)
{
	PUSH(pointer2cell(dict) + dicthead);
#ifdef CONFIG_DEBUG_INTERNAL
	printk("here: %x\n", pointer2cell(dict) + dicthead);
#endif
}

/*
 *  here!       ( new-dict-pointer -- )
 */

static void herewrite(void)
{
	ucell tmp = POP(); /* converted pointer */
	dicthead = tmp - pointer2cell(dict);
#ifdef CONFIG_DEBUG_INTERNAL
	printk("here!: new value: %x\n", tmp);
#endif

	if (dictlimit && dicthead >= dictlimit) {
	    printk("Dictionary space overflow:"
	            " dicthead=" FMT_ucellx
	            " dictlimit=" FMT_ucellx
	            "\n",
	            dicthead, dictlimit);
	}
}


/*
 *   emit       ( char --  )
 */

static void emit(void)
{
	cell tmp = POP();
#ifndef FCOMPILER
	putchar(tmp);
#else
       	put_outputbyte(tmp);
#endif
}


/*
 *   key?       (  -- pressed? )
 */

static void iskey(void)
{
	PUSH((cell) availchar());
}


/*
 *   key        (  -- char )
 */

static void key(void)
{
	while (!availchar());
#ifdef FCOMPILER
	PUSH(get_inputbyte());
#else
	PUSH(getchar());
#endif
}


/*
 *   ioc@       ( reg -- val )
 */

static void iocfetch(void)
{
#ifndef FCOMPILER
	cell reg = POP();
	PUSH(inb(reg));
#else
        (void)POP();
        PUSH(0);
#endif
}


/*
 *   iow@       ( reg -- val )
 */

static void iowfetch(void)
{
#ifndef FCOMPILER
	cell reg = POP();
	PUSH(inw(reg));
#else
        (void)POP();
        PUSH(0);
#endif
}

/*
 *   iol@       ( reg -- val )
 */

static void iolfetch(void)
{
#ifndef FCOMPILER
	cell reg = POP();
	PUSH(inl(reg));
#else
        (void)POP();
        PUSH(0);
#endif
}


/*
 *   ioc!       ( val reg --  )
 */

static void iocstore(void)
{
#ifndef FCOMPILER
	cell reg = POP();
	cell val = POP();

	outb(val, reg);
#else
        (void)POP();
        (void)POP();
#endif
}


/*
 *   iow!       ( val reg --  )
 */

static void iowstore(void)
{
#ifndef FCOMPILER
	cell reg = POP();
	cell val = POP();

	outw(val, reg);
#else
        (void)POP();
        (void)POP();
#endif
}


/*
 *   iol!       ( val reg --  )
 */

static void iolstore(void)
{
#ifndef FCOMPILER
	ucell reg = POP();
	ucell val = POP();

	outl(val, reg);
#else
        (void)POP();
        (void)POP();
#endif
}

/*
 *   i         ( -- i )
 */

static void loop_i(void)
{
	PUSH(rstack[rstackcnt]);
}

/*
 *   j         ( -- i )
 */

static void loop_j(void)
{
	PUSH(rstack[rstackcnt - 2]);
}

/* words[] is a function array of all native code functions used by
 * the dictionary, i.e. CFAs and primitives.
 * Any change here needs a matching change in the primitive word's
 * name list that is kept for bootstrapping in kernel/bootstrap.c
 *
 * NOTE: THIS LIST SHALL NOT CHANGE (EXCEPT MANDATORY ADDITIONS AT
 * THE END). ANY OTHER CHANGE WILL BREAK COMPATIBILITY TO OLDER
 * BINARY DICTIONARIES.
 */
static forth_word * const words[] = {
    /*
     * CFAs and special words
     */
    semis,
    docol,
    lit,
    docon,
    dovar,
    dodefer,
    dodoes,
    dodo,
    doisdo,
    doloop,
    doplusloop,
    doival,
    doivar,
    doidefer,

    /*
     * primitives
     */
    fdup,                   /* dup     */
    twodup,                 /* 2dup    */
    isdup,                  /* ?dup    */
    over,                   /* over    */
    twoover,                /* 2over   */
    pick,                   /* pick    */
    drop,                   /* drop    */
    twodrop,                /* 2drop   */
    nip,                    /* nip     */
    roll,                   /* roll    */
    rot,                    /* rot     */
    minusrot,               /* -rot    */
    swap,                   /* swap    */
    twoswap,                /* 2swap   */
    tor,                    /* >r      */
    rto,                    /* r>      */
    rfetch,                 /* r@      */
    depth,                  /* depth   */
    depthwrite,             /* depth!  */
    rdepth,                 /* rdepth  */
    rdepthwrite,            /* rdepth! */
    plus,                   /* +       */
    minus,                  /* -       */
    mult,                   /* *       */
    umult,                  /* u*      */
    mudivmod,               /* mu/mod  */
    forthabs,               /* abs     */
    negate,                 /* negate  */
    max,                    /* max     */
    min,                    /* min     */
    lshift,                 /* lshift  */
    rshift,                 /* rshift  */
    rshifta,                /* >>a     */
    and,                    /* and     */
    or,                     /* or      */
    xor,                    /* xor     */
    invert,                 /* invert  */
    dplus,                  /* d+      */
    dminus,                 /* d-      */
    mmult,                  /* m*      */
    ummult,                 /* um*     */
    fetch,                  /* @       */
    cfetch,                 /* c@      */
    wfetch,                 /* w@      */
    lfetch,                 /* l@      */
    store,                  /* !       */
    plusstore,              /* +!      */
    cstore,                 /* c!      */
    wstore,                 /* w!      */
    lstore,                 /* l!      */
    equals,                 /* =       */
    greater,                /* >       */
    less,                   /* <       */
    ugreater,               /* u>      */
    uless,                  /* u<      */
    spfetch,                /* sp@     */
    fmove,                  /* move    */
    ffill,                  /* fill    */
    emit,                   /* emit    */
    iskey,                  /* key?    */
    key,                    /* key     */
    execute,                /* execute */
    here,                   /* here    */
    herewrite,              /* here!   */
    dobranch,               /* dobranch     */
    docbranch,              /* do?branch    */
    unalignedwordread,      /* unaligned-w@ */
    unalignedwordwrite,     /* unaligned-w! */
    unalignedlongread,      /* unaligned-l@ */
    unalignedlongwrite,     /* unaligned-l! */
    iocfetch,               /* ioc@    */
    iowfetch,               /* iow@    */
    iolfetch,               /* iol@    */
    iocstore,               /* ioc!    */
    iowstore,               /* iow!    */
    iolstore,               /* iol!    */
    loop_i,                 /* i       */
    loop_j,                 /* j       */
    call,                   /* call    */
    sysdebug,               /* sys-debug */
    do_include,             /* $include */
    do_encode_file,         /* $encode-file */
    do_debug_xt,            /* (debug  */
    do_debug_off,           /* (debug-off) */
};
