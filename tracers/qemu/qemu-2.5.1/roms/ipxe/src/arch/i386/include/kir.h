#ifndef KIR_H
#define KIR_H

#ifndef KEEP_IT_REAL
#error "kir.h can be used only with -DKEEP_IT_REAL"
#endif

#ifdef ASSEMBLY

#define code32 code16gcc

#else /* ASSEMBLY */

__asm__ ( ".code16gcc" );

#endif /* ASSEMBLY */

#endif /* KIR_H */
