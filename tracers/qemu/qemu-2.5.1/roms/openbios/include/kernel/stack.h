/* stack.h
 * tag: stack and stack access functions
 *
 * Copyright (C) 2003 Patrick Mauritz, Stefan Reinauer
 *
 * See the file "COPYING" for further information about
 * the copyright and warranty status of this work.
 */

#ifndef __STACK_H
#define __STACK_H

#define dstacksize 512
extern int  dstackcnt;
extern cell dstack[dstacksize];

#define rstacksize 512
extern int  rstackcnt;
extern cell rstack[rstacksize];

extern int dbgrstackcnt;

//typedef struct opaque_xt *xt_t;
//typedef struct opaque_ihandle *ihandle_t;
//typedef struct opaque_phandle *phandle_t;

typedef ucell xt_t;
typedef ucell ihandle_t;
typedef ucell phandle_t;



#ifdef NATIVE_BITWIDTH_EQUALS_HOST_BITWIDTH

static inline ucell pointer2cell(const void* x)
{
    return (ucell)(uintptr_t)x;
}

static inline void* cell2pointer(ucell x)
{
    return (void*)(uintptr_t)x;
}

#endif

static inline void PUSH(ucell value) {
	dstack[++dstackcnt] = (value);
}
static inline void PUSH_xt( xt_t xt ) { PUSH( (ucell)xt ); }
static inline void PUSH_ih( ihandle_t ih ) { PUSH( (ucell)ih ); }
static inline void PUSH_ph( phandle_t ph ) { PUSH( (ucell)ph ); }

static inline ucell POP(void) {
	return (ucell) dstack[dstackcnt--];
}
static inline xt_t POP_xt( void ) { return (xt_t)POP(); }
static inline ihandle_t POP_ih( void ) { return (ihandle_t)POP(); }
static inline phandle_t POP_ph( void ) { return (phandle_t)POP(); }

static inline void DROP(void) {
	dstackcnt--;
}

static inline void DDROP(void) {
	dstackcnt -= 2;
}

static inline void DPUSH(ducell value) {
#ifdef NEED_FAKE_INT128_T
	dstack[++dstackcnt] = (cell) value.lo;
	dstack[++dstackcnt] = (cell) value.hi;
#else
	dstack[++dstackcnt] = (cell) value;
	dstack[++dstackcnt] = (cell) (value >> bitspercell);
#endif
}

static inline ducell DPOP(void) {
#ifdef NEED_FAKE_INT128_T
	ducell du;
	du.hi = (ucell) dstack[dstackcnt--];
	du.lo = (ucell) dstack[dstackcnt--];
	return du;
#else
	ducell du;
        du = ((ducell)(ucell) dstack[dstackcnt--]) << bitspercell;
	du |= (ucell) dstack[dstackcnt--];
	return du;
#endif
}

static inline ucell GETTOS(void) {
	return dstack[dstackcnt];
}

#define GETITEM(number) (dstack[dstackcnt - number])
static inline void PUSHR(ucell value) {
	rstack[++rstackcnt] = (value);
}

static inline ucell POPR(void) {
	return (ucell) rstack[rstackcnt--];
}
static inline ucell GETTORS(void) {
	return rstack[rstackcnt];
}


#if defined(DEBUG_DSTACK) || defined(FCOMPILER)
void printdstack(void);
#endif
#if defined(DEBUG_RSTACK) || defined(FCOMPILER)
void printrstack(void);
#endif

#endif
