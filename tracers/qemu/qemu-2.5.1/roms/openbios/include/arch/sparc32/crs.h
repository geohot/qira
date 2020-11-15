/*
 * Parts of asm-sparc/contregs.h
 *
 * contregs.h:  Addresses of registers in the ASI_CONTROL alternate address
 *              space. These are for the mmu's context register, etc.
 *
 * Copyright (C) 1995 David S. Miller (davem@caip.rutgers.edu)
 */
/* s=Swift, h=Ross_HyperSPARC, v=TI_Viking, t=Tsunami, r=Ross_Cypress        */
#define AC_M_PCR      0x0000        /* shv Processor Control Reg             */
#define AC_M_CTPR     0x0100        /* shv Context Table Pointer Reg         */
#define AC_M_CXR      0x0200        /* shv Context Register                  */
#define AC_M_SFSR     0x0300        /* shv Synchronous Fault Status Reg      */
#define AC_M_SFAR     0x0400        /* shv Synchronous Fault Address Reg     */
