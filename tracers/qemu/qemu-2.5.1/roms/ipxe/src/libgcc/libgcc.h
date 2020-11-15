#ifndef _LIBGCC_H
#define _LIBGCC_H

#include <stdint.h>
#include <stddef.h>

extern __libgcc uint64_t __udivmoddi4 ( uint64_t num, uint64_t den,
					uint64_t *rem );
extern __libgcc uint64_t __udivdi3  (uint64_t num, uint64_t den );
extern __libgcc uint64_t __umoddi3 ( uint64_t num, uint64_t den );
extern __libgcc int64_t __divdi3 ( int64_t num, int64_t den );
extern __libgcc int64_t __moddi3 ( int64_t num, int64_t den );

#endif /* _LIBGCC_H */
