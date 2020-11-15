/*
*****************************************************************************
**                                                                          *
**  Copyright © 1993, 1994						    *
**  by Digital Equipment Corporation, Maynard, Massachusetts.		    *
**                                                                          *
**  All Rights Reserved							    *
**                                                                          *
**  Permission  is  hereby  granted  to  use, copy, modify and distribute   *
**  this  software  and  its  documentation,  in  both  source  code  and   *
**  object  code  form,  and without fee, for the purpose of distribution   *
**  of this software  or  modifications  of this software within products   *
**  incorporating  an  integrated   circuit  implementing  Digital's  AXP   *
**  architecture,  regardless  of the  source of such integrated circuit,   *
**  provided that the  above copyright  notice and this permission notice   *
**  appear  in  all copies,  and  that  the  name  of  Digital  Equipment   *
**  Corporation  not  be  used  in advertising or publicity pertaining to   *
**  distribution of the  document  or  software without specific, written   *
**  prior permission.							    *
**                                                                          *
**  Digital  Equipment  Corporation   disclaims  all   warranties  and/or   *
**  guarantees  with  regard  to  this  software,  including  all implied   *
**  warranties of fitness for  a  particular purpose and merchantability,   *
**  and makes  no  representations  regarding  the use of, or the results   *
**  of the use of, the software and documentation in terms of correctness,  *
**  accuracy,  reliability,  currentness  or  otherwise;  and you rely on   *
**  the software, documentation and results solely at your own risk.	    *
**                                                                          *
**  AXP is a trademark of Digital Equipment Corporation.		    *
**                                                                          *
*****************************************************************************
*/

/*
**  Seg0 and Seg1 Virtual Address (VA) Format
**
**	  Loc	Size	Name	Function
**	 -----	----	----	---------------------------------
**	<42:33>  10	SEG1	First level page table offset
**	<32:23>  10	SEG2	Second level page table offset
**	<22:13>  10	SEG3	Third level page table offset
**	<12:00>  13	OFFSET	Byte within page offset
*/

#define VA_V_SEG1	33
#define	VA_M_SEG1	(0x3FF<<VA_V_SEG1)
#define VA_V_SEG2	23
#define VA_M_SEG2	(0x3FF<<VA_V_SEG2)
#define VA_V_SEG3	13
#define VA_M_SEG3	(0x3FF<<VA_V_SEG3)
#define VA_V_OFFSET	0
#define VA_M_OFFSET	0x1FFF

/*
**  Virtual Address Options: 8K byte page size
*/

#define	VA_S_SIZE	43
#define	VA_S_OFF	13
#define VA_S_SEG	10
#define VA_S_PAGE_SIZE	8192

/*
**  Page Table Entry (PTE) Format
**
**	 Extent	Size	Name	Function
**	 ------	----	----	---------------------------------
**	<63:32>	  32	PFN	Page Frame Number
**	<31:16>	  16	SW	Reserved for software
**	<15:14>	   2	RSV0	Reserved for hardware SBZ
**	   <13>	   1	UWE	User Write Enable
**	   <12>	   1	KWE	Kernel Write Enable
**	<11:10>	   2	RSV1	Reserved for hardware SBZ
**	    <9>	   1	URE	User Read Enable
**	    <8>	   1	KRE	Kernel Read Enable
**	    <7>	   1	RSV2	Reserved for hardware SBZ
**	  <6:5>	   2	GH	Granularity Hint
**	    <4>	   1	ASM	Address Space Match
**	    <3>	   1	FOE	Fault On Execute
**	    <2>	   1	FOW	Fault On Write
**	    <1>	   1	FOR	Fault On Read
**	    <0>	   1	V	Valid
*/

#define	PTE_V_PFN	32
#define PTE_M_PFN	0xFFFFFFFF00000000
#define PTE_V_SW	16
#define PTE_M_SW	0x00000000FFFF0000
#define PTE_V_UWE	13
#define PTE_M_UWE	(1<<PTE_V_UWE)
#define PTE_V_KWE	12
#define PTE_M_KWE	(1<<PTE_V_KWE)
#define PTE_V_URE	9
#define PTE_M_URE	(1<<PTE_V_URE)
#define PTE_V_KRE	8
#define PTE_M_KRE	(1<<PTE_V_KRE)
#define PTE_V_GH	5
#define PTE_M_GH	(3<<PTE_V_GH)
#define PTE_V_ASM	4
#define PTE_M_ASM	(1<<PTE_V_ASM)
#define PTE_V_FOE	3
#define PTE_M_FOE	(1<<PTE_V_FOE)
#define PTE_V_FOW	2
#define PTE_M_FOW	(1<<PTE_V_FOW)
#define PTE_V_FOR	1
#define PTE_M_FOR	(1<<PTE_V_FOR)
#define PTE_V_VALID	0
#define PTE_M_VALID	(1<<PTE_V_VALID)

#define PTE_M_KSEG	0x1111
#define PTE_M_PROT	0x3300

/*
**  System Entry Instruction Fault (entIF) Constants:
*/

#define IF_K_BPT        0x0
#define IF_K_BUGCHK     0x1
#define IF_K_GENTRAP    0x2
#define IF_K_FEN        0x3
#define IF_K_OPCDEC     0x4

/*
**  System Entry Hardware Interrupt (entInt) Constants:
*/

#define INT_K_IP	0x0
#define INT_K_CLK	0x1
#define INT_K_MCHK	0x2
#define INT_K_DEV	0x3
#define INT_K_PERF	0x4

/*
**  System Entry MM Fault (entMM) Constants:
*/

#define	MM_K_TNV	0x0
#define MM_K_ACV	0x1
#define MM_K_FOR	0x2
#define MM_K_FOE	0x3
#define MM_K_FOW	0x4

/*
**  Process Control Block (PCB) Offsets:
*/

#define PCB_Q_KSP	0x0000
#define PCB_Q_USP	0x0008
#define PCB_Q_PTBR	0x0010
#define PCB_L_PCC	0x0018
#define PCB_L_ASN	0x001C
#define PCB_Q_UNIQUE	0x0020
#define PCB_Q_FEN	0x0028
#define PCB_Q_RSV0	0x0030
#define PCB_Q_RSV1	0x0038

/*
**  Processor Status Register (PS) Bit Summary
**
**	Extent	Size	Name	Function
**	------	----	----	---------------------------------
**	  <3>	 1	CM	Current Mode
**	<2:0>	 3	IPL	Interrupt Priority Level
**/

#define	PS_V_CM		3
#define PS_M_CM		(1<<PS_V_CM)
#define	PS_V_IPL	0
#define	PS_M_IPL	(7<<PS_V_IPL)

#define	PS_K_KERN	(0<<PS_V_CM)
#define PS_K_USER	(1<<PS_V_CM)

#define	IPL_K_ZERO	0x0
#define IPL_K_SW0	0x1
#define IPL_K_SW1	0x2
#define IPL_K_DEV0	0x3
#define IPL_K_DEV1	0x4
#define IPL_K_CLK	0x5
#define IPL_K_IP	0x6
#define IPL_K_RT	0x6
#define IPL_K_PERF      0x6
#define IPL_K_PFAIL     0x6
#define IPL_K_MCHK	0x7

#define IPL_K_LOW	0x0
#define IPL_K_HIGH	0x7

/*
**  SCB Offset Definitions:
*/

#define SCB_Q_FEN	    	0x0010
#define SCB_Q_ACV		0x0080
#define SCB_Q_TNV		0x0090
#define SCB_Q_FOR		0x00A0
#define SCB_Q_FOW		0x00B0
#define SCB_Q_FOE		0x00C0
#define SCB_Q_ARITH		0x0200
#define SCB_Q_KAST		0x0240
#define SCB_Q_EAST		0x0250
#define SCB_Q_SAST		0x0260
#define SCB_Q_UAST		0x0270
#define SCB_Q_UNALIGN		0x0280
#define SCB_Q_BPT		0x0400
#define SCB_Q_BUGCHK		0x0410
#define SCB_Q_OPCDEC		0x0420
#define SCB_Q_ILLPAL		0x0430
#define SCB_Q_TRAP		0x0440
#define SCB_Q_CHMK		0x0480
#define SCB_Q_CHME		0x0490
#define SCB_Q_CHMS		0x04A0
#define SCB_Q_CHMU		0x04B0
#define SCB_Q_SW0		0x0500
#define SCB_Q_SW1		0x0510
#define SCB_Q_SW2		0x0520
#define SCB_Q_SW3		0x0530
#define	SCB_Q_SW4		0x0540
#define SCB_Q_SW5		0x0550
#define SCB_Q_SW6		0x0560
#define SCB_Q_SW7		0x0570
#define SCB_Q_SW8		0x0580
#define SCB_Q_SW9		0x0590
#define SCB_Q_SW10		0x05A0
#define SCB_Q_SW11		0x05B0
#define SCB_Q_SW12		0x05C0
#define SCB_Q_SW13		0x05D0
#define SCB_Q_SW14		0x05E0
#define SCB_Q_SW15		0x05F0
#define SCB_Q_CLOCK		0x0600
#define SCB_Q_INTER		0x0610
#define SCB_Q_SYSERR        	0x0620
#define SCB_Q_PROCERR		0x0630
#define SCB_Q_PWRFAIL		0x0640
#define SCB_Q_PERFMON		0x0650
#define SCB_Q_SYSMCHK		0x0660
#define SCB_Q_PROCMCHK      	0x0670
#define SCB_Q_PASSREL		0x0680

/*
**  Stack Frame (FRM) Offsets:
**
**  There are two types of system entries for OSF/1 - those for the
**  callsys CALL_PAL function and those for exceptions and interrupts.
**  Both entry types use the same stack frame layout.  The stack frame
**  contains space for the PC, the PS, the saved GP, and the saved
**  argument registers a0, a1, and a2.  On entry, SP points to the
**  saved PS.
*/

#define	FRM_Q_PS	0x0000
#define FRM_Q_PC	0x0008
#define FRM_Q_GP	0x0010
#define FRM_Q_A0	0x0018
#define FRM_Q_A1	0x0020
#define FRM_Q_A2	0x0028

#define FRM_K_SIZE	48

/*
**  Halt Codes:
*/

#define HLT_K_RESET	    0x0000
#define HLT_K_HW_HALT	    0x0001
#define HLT_K_KSP_INVAL	    0x0002
#define HLT_K_SCBB_INVAL    0x0003
#define HLT_K_PTBR_INVAL    0x0004
#define HLT_K_SW_HALT	    0x0005
#define HLT_K_DBL_MCHK	    0x0006
#define HLT_K_MCHK_FROM_PAL 0x0007

/*
**  Machine Check Codes:
*/

#define MCHK_K_TPERR	    0x0080
#define MCHK_K_TCPERR	    0x0082
#define MCHK_K_HERR	    0x0084
#define MCHK_K_ECC_C	    0x0086
#define MCHK_K_ECC_NC	    0x0088
#define MCHK_K_UNKNOWN	    0x008A
#define MCHK_K_CACKSOFT	    0x008C
#define MCHK_K_BUGCHECK	    0x008E
#define MCHK_K_OS_BUGCHECK  0x0090
#define MCHK_K_DCPERR	    0x0092
#define MCHK_K_ICPERR	    0x0094
#define MCHK_K_RETRY_IRD    0x0096
#define MCHK_K_PROC_HERR    0x0098

/*
** System Machine Check Codes:
*/

#define MCHK_K_READ_NXM     0x0200
#define MCHK_K_SYS_HERR     0x0202

/*
**  Machine Check Error Status Summary (MCES) Register Format
**
**	 Extent	Size	Name	Function
**	 ------	----	----	---------------------------------
**	  <0>	  1	MIP	Machine check in progress
**	  <1>	  1	SCE	System correctable error in progress
**	  <2>	  1	PCE	Processor correctable error in progress
**	  <3>	  1	DPC	Disable PCE error reporting
**	  <4>	  1	DSC	Disable SCE error reporting
*/

#define MCES_V_MIP	0
#define MCES_M_MIP	(1<<MCES_V_MIP)
#define MCES_V_SCE	1
#define MCES_M_SCE	(1<<MCES_V_SCE)
#define MCES_V_PCE	2
#define MCES_M_PCE	(1<<MCES_V_PCE)
#define MCES_V_DPC	3
#define MCES_M_DPC	(1<<MCES_V_DPC)
#define MCES_V_DSC	4
#define MCES_M_DSC	(1<<MCES_V_DSC)

#define MCES_M_ALL      (MCES_M_MIP | MCES_M_SCE | MCES_M_PCE | MCES_M_DPC \
                         | MCES_M_DSC)

/*
**  Who-Am-I (WHAMI) Register Format
**
**	 Extent	Size	Name	Function
**	 ------	----	----	---------------------------------
**	  <7:0>	  8	ID	Who-Am-I identifier
**	  <15:8>   1	SWAP	Swap PALcode flag - character 'S'
*/

#define WHAMI_V_SWAP	8
#define WHAMI_M_SWAP	(1<<WHAMI_V_SWAP)
#define WHAMI_V_ID	0
#define WHAMI_M_ID	0xFF

#define WHAMI_K_SWAP    0x53    /* Character 'S' */

/*
 * OSF/1 PAL-code-imposed page table bits
 */
#define _PAGE_VALID     0x0001
#define _PAGE_FOR       0x0002  /* used for page protection (fault on read) */
#define _PAGE_FOW       0x0004  /* used for page protection (fault on write) */
#define _PAGE_FOE       0x0008  /* used for page protection (fault on exec) */
#define _PAGE_ASM       0x0010
#define _PAGE_KRE       0x0100  /* xxx - see below on the "accessed" bit */
#define _PAGE_URE       0x0200  /* xxx */
#define _PAGE_KWE       0x1000  /* used to do the dirty bit in software */
#define _PAGE_UWE       0x2000  /* used to do the dirty bit in software */
