/* ISA I/O mapped NS8390-based cards, including NE2000 */
#if 0 /* Currently broken! */
#define INCLUDE_NE 1
#define NE_SCAN 0x300,0x280,0x320,0x340,0x380
#include "ns8390.c"
#endif
