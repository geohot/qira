/******************************************************************************
 * Copyright (c) 2004, 2008 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/
#ifndef PCD_H
#define PCD_H

#define PCD_START_ADDR 0xFF00000       // FIXME: this should not interfere with
				       // other parts of the firmware
#define PCD_HDR_SIZE   (6 * 8)   /* only use for ctrl file */

/* PCD File Definition ****************************************/
/* File = "p:ctrl"   0x703a6374726c0000                       */
/* Data :                                                     */
/* [00:07] - pointer to header of last file which was created */
/* [08:0f] - pointer to header of next file for creation      */
/**************************************************************/
#define PCDF_CTRL_LAST	0
#define PCDF_CTRL_NEXT  8

/* PCD File Definition ****************************************/
/* File = "p:pXmem"                                           */
/* Data :                                                     */
/* [00:07] - number of memory segments                        */
/* [08:0f] - real base of memory segment #n                   */
/* [10:17] - real size of memory segment #n                   */
/* [18:1f] - real base of memory segment #n+1                 */
/* [20:27] - real size of memory segment #n+1                 */
/* ... and so on..                                            */
/**************************************************************/
#define PCDF_MEM_NUM       0
#define PCDF_MEMN_BASE(N)  (8 + ((N) * 16))
#define PCDF_MEMN_SIZE(M)  (PCDF_MEMN_BASE(M) + 8)

/* PCD File Definition ****************************************/
/* File = "p:pXcfg"                                           */
/* Data :                                                     */
/* [00:07] - number of memory segments                        */
/* [08:0f] - real base of memory segment #n                   */
/* [10:17] - real size of memory segment #n                   */
/* [18:1f] - real base of memory segment #n+1                 */
/* [20:27] - real size of memory segment #n+1                 */
/* ... and so on..                                            */
/**************************************************************/
#define PCDF_PCFG_IOCBASE	(0 * 8)
#define PCDF_PCFG_BPBASE	(1 * 8)
#define PCDF_PCFG_SPUMAP	(2 * 8)
#define PCDF_PCFG_TIMEBASE	(3 * 8)
#define PCDF_PCFG_CPUFREQ   (4 * 8)

#endif
