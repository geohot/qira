/*
 * Copyright (c) 2008, 2009 QLogic Corporation. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
/* This file is mechanically generated from RTL. Any hand-edits will be lost! */

/* This file has been further processed by ./drivers/infiniband/qib_genbits.pl */

FILE_LICENCE ( GPL2_ONLY );

#define QIB_7322_Revision_offset 0x00000000UL
struct QIB_7322_Revision_pb {
	pseudo_bit_t R_ChipRevMinor[8];
	pseudo_bit_t R_ChipRevMajor[8];
	pseudo_bit_t R_Arch[8];
	pseudo_bit_t R_SW[8];
	pseudo_bit_t BoardID[8];
	pseudo_bit_t R_Emulation_Revcode[22];
	pseudo_bit_t R_Emulation[1];
	pseudo_bit_t R_Simulator[1];
};
struct QIB_7322_Revision {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_Revision_pb );
};
/* Default value: 0x0000000002010601 */

#define QIB_7322_Control_offset 0x00000008UL
struct QIB_7322_Control_pb {
	pseudo_bit_t SyncReset[1];
	pseudo_bit_t FreezeMode[1];
	pseudo_bit_t _unused_0[1];
	pseudo_bit_t PCIERetryBufDiagEn[1];
	pseudo_bit_t SDmaDescFetchPriorityEn[1];
	pseudo_bit_t PCIEPostQDiagEn[1];
	pseudo_bit_t PCIECplQDiagEn[1];
	pseudo_bit_t _unused_1[57];
};
struct QIB_7322_Control {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_Control_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_PageAlign_offset 0x00000010UL
/* Default value: 0x0000000000001000 */

#define QIB_7322_ContextCnt_offset 0x00000018UL
/* Default value: 0x0000000000000012 */

#define QIB_7322_Scratch_offset 0x00000020UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_CntrRegBase_offset 0x00000028UL
/* Default value: 0x0000000000011000 */

#define QIB_7322_SendRegBase_offset 0x00000030UL
/* Default value: 0x0000000000003000 */

#define QIB_7322_UserRegBase_offset 0x00000038UL
/* Default value: 0x0000000000200000 */

#define QIB_7322_DebugPortSel_offset 0x00000040UL
struct QIB_7322_DebugPortSel_pb {
	pseudo_bit_t DebugOutMuxSel[2];
	pseudo_bit_t _unused_0[28];
	pseudo_bit_t SrcMuxSel0[8];
	pseudo_bit_t SrcMuxSel1[8];
	pseudo_bit_t DbgClkPortSel[5];
	pseudo_bit_t EnDbgPort[1];
	pseudo_bit_t EnEnhancedDebugMode[1];
	pseudo_bit_t EnhMode_SrcMuxSelIndex[10];
	pseudo_bit_t EnhMode_SrcMuxSelWrEn[1];
};
struct QIB_7322_DebugPortSel {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_DebugPortSel_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_DebugPortNibbleSel_offset 0x00000048UL
struct QIB_7322_DebugPortNibbleSel_pb {
	pseudo_bit_t NibbleSel0[4];
	pseudo_bit_t NibbleSel1[4];
	pseudo_bit_t NibbleSel2[4];
	pseudo_bit_t NibbleSel3[4];
	pseudo_bit_t NibbleSel4[4];
	pseudo_bit_t NibbleSel5[4];
	pseudo_bit_t NibbleSel6[4];
	pseudo_bit_t NibbleSel7[4];
	pseudo_bit_t NibbleSel8[4];
	pseudo_bit_t NibbleSel9[4];
	pseudo_bit_t NibbleSel10[4];
	pseudo_bit_t NibbleSel11[4];
	pseudo_bit_t NibbleSel12[4];
	pseudo_bit_t NibbleSel13[4];
	pseudo_bit_t NibbleSel14[4];
	pseudo_bit_t NibbleSel15[4];
};
struct QIB_7322_DebugPortNibbleSel {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_DebugPortNibbleSel_pb );
};
/* Default value: 0xFEDCBA9876543210 */

#define QIB_7322_DebugSigsIntSel_offset 0x00000050UL
struct QIB_7322_DebugSigsIntSel_pb {
	pseudo_bit_t debug_port_sel_pcs_pipe_lane07[3];
	pseudo_bit_t debug_port_sel_pcs_pipe_lane815[3];
	pseudo_bit_t debug_port_sel_pcs_sdout[1];
	pseudo_bit_t debug_port_sel_pcs_symlock_elfifo_lane[4];
	pseudo_bit_t debug_port_sel_pcs_rxdet_encdec_lane[3];
	pseudo_bit_t EnableSDma_SelfDrain[1];
	pseudo_bit_t debug_port_sel_pcie_rx_tx[1];
	pseudo_bit_t _unused_0[1];
	pseudo_bit_t debug_port_sel_tx_ibport[1];
	pseudo_bit_t debug_port_sel_tx_sdma[1];
	pseudo_bit_t debug_port_sel_rx_ibport[1];
	pseudo_bit_t _unused_1[12];
	pseudo_bit_t debug_port_sel_xgxs_0[4];
	pseudo_bit_t debug_port_sel_credit_a_0[3];
	pseudo_bit_t debug_port_sel_credit_b_0[3];
	pseudo_bit_t debug_port_sel_xgxs_1[4];
	pseudo_bit_t debug_port_sel_credit_a_1[3];
	pseudo_bit_t debug_port_sel_credit_b_1[3];
	pseudo_bit_t _unused_2[12];
};
struct QIB_7322_DebugSigsIntSel {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_DebugSigsIntSel_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_DebugPortValueReg_offset 0x00000058UL

#define QIB_7322_IntBlocked_offset 0x00000060UL
struct QIB_7322_IntBlocked_pb {
	pseudo_bit_t RcvAvail0IntBlocked[1];
	pseudo_bit_t RcvAvail1IntBlocked[1];
	pseudo_bit_t RcvAvail2IntBlocked[1];
	pseudo_bit_t RcvAvail3IntBlocked[1];
	pseudo_bit_t RcvAvail4IntBlocked[1];
	pseudo_bit_t RcvAvail5IntBlocked[1];
	pseudo_bit_t RcvAvail6IntBlocked[1];
	pseudo_bit_t RcvAvail7IntBlocked[1];
	pseudo_bit_t RcvAvail8IntBlocked[1];
	pseudo_bit_t RcvAvail9IntBlocked[1];
	pseudo_bit_t RcvAvail10IntBlocked[1];
	pseudo_bit_t RcvAvail11IntBlocked[1];
	pseudo_bit_t RcvAvail12IntBlocked[1];
	pseudo_bit_t RcvAvail13IntBlocked[1];
	pseudo_bit_t RcvAvail14IntBlocked[1];
	pseudo_bit_t RcvAvail15IntBlocked[1];
	pseudo_bit_t RcvAvail16IntBlocked[1];
	pseudo_bit_t RcvAvail17IntBlocked[1];
	pseudo_bit_t _unused_0[5];
	pseudo_bit_t SendBufAvailIntBlocked[1];
	pseudo_bit_t SendDoneIntBlocked_0[1];
	pseudo_bit_t SendDoneIntBlocked_1[1];
	pseudo_bit_t _unused_1[2];
	pseudo_bit_t AssertGPIOIntBlocked[1];
	pseudo_bit_t ErrIntBlocked[1];
	pseudo_bit_t ErrIntBlocked_0[1];
	pseudo_bit_t ErrIntBlocked_1[1];
	pseudo_bit_t RcvUrg0IntBlocked[1];
	pseudo_bit_t RcvUrg1IntBlocked[1];
	pseudo_bit_t RcvUrg2IntBlocked[1];
	pseudo_bit_t RcvUrg3IntBlocked[1];
	pseudo_bit_t RcvUrg4IntBlocked[1];
	pseudo_bit_t RcvUrg5IntBlocked[1];
	pseudo_bit_t RcvUrg6IntBlocked[1];
	pseudo_bit_t RcvUrg7IntBlocked[1];
	pseudo_bit_t RcvUrg8IntBlocked[1];
	pseudo_bit_t RcvUrg9IntBlocked[1];
	pseudo_bit_t RcvUrg10IntBlocked[1];
	pseudo_bit_t RcvUrg11IntBlocked[1];
	pseudo_bit_t RcvUrg12IntBlocked[1];
	pseudo_bit_t RcvUrg13IntBlocked[1];
	pseudo_bit_t RcvUrg14IntBlocked[1];
	pseudo_bit_t RcvUrg15IntBlocked[1];
	pseudo_bit_t RcvUrg16IntBlocked[1];
	pseudo_bit_t RcvUrg17IntBlocked[1];
	pseudo_bit_t _unused_2[6];
	pseudo_bit_t SDmaCleanupDoneBlocked_0[1];
	pseudo_bit_t SDmaCleanupDoneBlocked_1[1];
	pseudo_bit_t SDmaIdleIntBlocked_0[1];
	pseudo_bit_t SDmaIdleIntBlocked_1[1];
	pseudo_bit_t SDmaProgressIntBlocked_0[1];
	pseudo_bit_t SDmaProgressIntBlocked_1[1];
	pseudo_bit_t SDmaIntBlocked_0[1];
	pseudo_bit_t SDmaIntBlocked_1[1];
};
struct QIB_7322_IntBlocked {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_IntBlocked_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_IntMask_offset 0x00000068UL
struct QIB_7322_IntMask_pb {
	pseudo_bit_t RcvAvail0IntMask[1];
	pseudo_bit_t RcvAvail1IntMask[1];
	pseudo_bit_t RcvAvail2IntMask[1];
	pseudo_bit_t RcvAvail3IntMask[1];
	pseudo_bit_t RcvAvail4IntMask[1];
	pseudo_bit_t RcvAvail5IntMask[1];
	pseudo_bit_t RcvAvail6IntMask[1];
	pseudo_bit_t RcvAvail7IntMask[1];
	pseudo_bit_t RcvAvail8IntMask[1];
	pseudo_bit_t RcvAvail9IntMask[1];
	pseudo_bit_t RcvAvail10IntMask[1];
	pseudo_bit_t RcvAvail11IntMask[1];
	pseudo_bit_t RcvAvail12IntMask[1];
	pseudo_bit_t RcvAvail13IntMask[1];
	pseudo_bit_t RcvAvail14IntMask[1];
	pseudo_bit_t RcvAvail15IntMask[1];
	pseudo_bit_t RcvAvail16IntMask[1];
	pseudo_bit_t RcvAvail17IntMask[1];
	pseudo_bit_t _unused_0[5];
	pseudo_bit_t SendBufAvailIntMask[1];
	pseudo_bit_t SendDoneIntMask_0[1];
	pseudo_bit_t SendDoneIntMask_1[1];
	pseudo_bit_t _unused_1[2];
	pseudo_bit_t AssertGPIOIntMask[1];
	pseudo_bit_t ErrIntMask[1];
	pseudo_bit_t ErrIntMask_0[1];
	pseudo_bit_t ErrIntMask_1[1];
	pseudo_bit_t RcvUrg0IntMask[1];
	pseudo_bit_t RcvUrg1IntMask[1];
	pseudo_bit_t RcvUrg2IntMask[1];
	pseudo_bit_t RcvUrg3IntMask[1];
	pseudo_bit_t RcvUrg4IntMask[1];
	pseudo_bit_t RcvUrg5IntMask[1];
	pseudo_bit_t RcvUrg6IntMask[1];
	pseudo_bit_t RcvUrg7IntMask[1];
	pseudo_bit_t RcvUrg8IntMask[1];
	pseudo_bit_t RcvUrg9IntMask[1];
	pseudo_bit_t RcvUrg10IntMask[1];
	pseudo_bit_t RcvUrg11IntMask[1];
	pseudo_bit_t RcvUrg12IntMask[1];
	pseudo_bit_t RcvUrg13IntMask[1];
	pseudo_bit_t RcvUrg14IntMask[1];
	pseudo_bit_t RcvUrg15IntMask[1];
	pseudo_bit_t RcvUrg16IntMask[1];
	pseudo_bit_t RcvUrg17IntMask[1];
	pseudo_bit_t _unused_2[6];
	pseudo_bit_t SDmaCleanupDoneMask_0[1];
	pseudo_bit_t SDmaCleanupDoneMask_1[1];
	pseudo_bit_t SDmaIdleIntMask_0[1];
	pseudo_bit_t SDmaIdleIntMask_1[1];
	pseudo_bit_t SDmaProgressIntMask_0[1];
	pseudo_bit_t SDmaProgressIntMask_1[1];
	pseudo_bit_t SDmaIntMask_0[1];
	pseudo_bit_t SDmaIntMask_1[1];
};
struct QIB_7322_IntMask {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_IntMask_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_IntStatus_offset 0x00000070UL
struct QIB_7322_IntStatus_pb {
	pseudo_bit_t RcvAvail0[1];
	pseudo_bit_t RcvAvail1[1];
	pseudo_bit_t RcvAvail2[1];
	pseudo_bit_t RcvAvail3[1];
	pseudo_bit_t RcvAvail4[1];
	pseudo_bit_t RcvAvail5[1];
	pseudo_bit_t RcvAvail6[1];
	pseudo_bit_t RcvAvail7[1];
	pseudo_bit_t RcvAvail8[1];
	pseudo_bit_t RcvAvail9[1];
	pseudo_bit_t RcvAvail10[1];
	pseudo_bit_t RcvAvail11[1];
	pseudo_bit_t RcvAvail12[1];
	pseudo_bit_t RcvAvail13[1];
	pseudo_bit_t RcvAvail14[1];
	pseudo_bit_t RcvAvail15[1];
	pseudo_bit_t RcvAvail16[1];
	pseudo_bit_t RcvAvail17[1];
	pseudo_bit_t _unused_0[5];
	pseudo_bit_t SendBufAvail[1];
	pseudo_bit_t SendDone_0[1];
	pseudo_bit_t SendDone_1[1];
	pseudo_bit_t _unused_1[2];
	pseudo_bit_t AssertGPIO[1];
	pseudo_bit_t Err[1];
	pseudo_bit_t Err_0[1];
	pseudo_bit_t Err_1[1];
	pseudo_bit_t RcvUrg0[1];
	pseudo_bit_t RcvUrg1[1];
	pseudo_bit_t RcvUrg2[1];
	pseudo_bit_t RcvUrg3[1];
	pseudo_bit_t RcvUrg4[1];
	pseudo_bit_t RcvUrg5[1];
	pseudo_bit_t RcvUrg6[1];
	pseudo_bit_t RcvUrg7[1];
	pseudo_bit_t RcvUrg8[1];
	pseudo_bit_t RcvUrg9[1];
	pseudo_bit_t RcvUrg10[1];
	pseudo_bit_t RcvUrg11[1];
	pseudo_bit_t RcvUrg12[1];
	pseudo_bit_t RcvUrg13[1];
	pseudo_bit_t RcvUrg14[1];
	pseudo_bit_t RcvUrg15[1];
	pseudo_bit_t RcvUrg16[1];
	pseudo_bit_t RcvUrg17[1];
	pseudo_bit_t _unused_2[6];
	pseudo_bit_t SDmaCleanupDone_0[1];
	pseudo_bit_t SDmaCleanupDone_1[1];
	pseudo_bit_t SDmaIdleInt_0[1];
	pseudo_bit_t SDmaIdleInt_1[1];
	pseudo_bit_t SDmaProgressInt_0[1];
	pseudo_bit_t SDmaProgressInt_1[1];
	pseudo_bit_t SDmaInt_0[1];
	pseudo_bit_t SDmaInt_1[1];
};
struct QIB_7322_IntStatus {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_IntStatus_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_IntClear_offset 0x00000078UL
struct QIB_7322_IntClear_pb {
	pseudo_bit_t RcvAvail0IntClear[1];
	pseudo_bit_t RcvAvail1IntClear[1];
	pseudo_bit_t RcvAvail2IntClear[1];
	pseudo_bit_t RcvAvail3IntClear[1];
	pseudo_bit_t RcvAvail4IntClear[1];
	pseudo_bit_t RcvAvail5IntClear[1];
	pseudo_bit_t RcvAvail6IntClear[1];
	pseudo_bit_t RcvAvail7IntClear[1];
	pseudo_bit_t RcvAvail8IntClear[1];
	pseudo_bit_t RcvAvail9IntClear[1];
	pseudo_bit_t RcvAvail10IntClear[1];
	pseudo_bit_t RcvAvail11IntClear[1];
	pseudo_bit_t RcvAvail12IntClear[1];
	pseudo_bit_t RcvAvail13IntClear[1];
	pseudo_bit_t RcvAvail14IntClear[1];
	pseudo_bit_t RcvAvail15IntClear[1];
	pseudo_bit_t RcvAvail16IntClear[1];
	pseudo_bit_t RcvAvail17IntClear[1];
	pseudo_bit_t _unused_0[5];
	pseudo_bit_t SendBufAvailIntClear[1];
	pseudo_bit_t SendDoneIntClear_0[1];
	pseudo_bit_t SendDoneIntClear_1[1];
	pseudo_bit_t _unused_1[2];
	pseudo_bit_t AssertGPIOIntClear[1];
	pseudo_bit_t ErrIntClear[1];
	pseudo_bit_t ErrIntClear_0[1];
	pseudo_bit_t ErrIntClear_1[1];
	pseudo_bit_t RcvUrg0IntClear[1];
	pseudo_bit_t RcvUrg1IntClear[1];
	pseudo_bit_t RcvUrg2IntClear[1];
	pseudo_bit_t RcvUrg3IntClear[1];
	pseudo_bit_t RcvUrg4IntClear[1];
	pseudo_bit_t RcvUrg5IntClear[1];
	pseudo_bit_t RcvUrg6IntClear[1];
	pseudo_bit_t RcvUrg7IntClear[1];
	pseudo_bit_t RcvUrg8IntClear[1];
	pseudo_bit_t RcvUrg9IntClear[1];
	pseudo_bit_t RcvUrg10IntClear[1];
	pseudo_bit_t RcvUrg11IntClear[1];
	pseudo_bit_t RcvUrg12IntClear[1];
	pseudo_bit_t RcvUrg13IntClear[1];
	pseudo_bit_t RcvUrg14IntClear[1];
	pseudo_bit_t RcvUrg15IntClear[1];
	pseudo_bit_t RcvUrg16IntClear[1];
	pseudo_bit_t RcvUrg17IntClear[1];
	pseudo_bit_t _unused_2[6];
	pseudo_bit_t SDmaCleanupDoneClear_0[1];
	pseudo_bit_t SDmaCleanupDoneClear_1[1];
	pseudo_bit_t SDmaIdleIntClear_0[1];
	pseudo_bit_t SDmaIdleIntClear_1[1];
	pseudo_bit_t SDmaProgressIntClear_0[1];
	pseudo_bit_t SDmaProgressIntClear_1[1];
	pseudo_bit_t SDmaIntClear_0[1];
	pseudo_bit_t SDmaIntClear_1[1];
};
struct QIB_7322_IntClear {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_IntClear_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_ErrMask_offset 0x00000080UL
struct QIB_7322_ErrMask_pb {
	pseudo_bit_t _unused_0[12];
	pseudo_bit_t RcvEgrFullErrMask[1];
	pseudo_bit_t RcvHdrFullErrMask[1];
	pseudo_bit_t _unused_1[11];
	pseudo_bit_t SDmaBufMaskDuplicateErrMask[1];
	pseudo_bit_t SDmaWrongPortErrMask[1];
	pseudo_bit_t SendSpecialTriggerErrMask[1];
	pseudo_bit_t _unused_2[7];
	pseudo_bit_t SendArmLaunchErrMask[1];
	pseudo_bit_t SendVLMismatchErrMask[1];
	pseudo_bit_t _unused_3[15];
	pseudo_bit_t RcvContextShareErrMask[1];
	pseudo_bit_t InvalidEEPCmdMask[1];
	pseudo_bit_t _unused_4[1];
	pseudo_bit_t SBufVL15MisUseErrMask[1];
	pseudo_bit_t SDmaVL15ErrMask[1];
	pseudo_bit_t _unused_5[4];
	pseudo_bit_t InvalidAddrErrMask[1];
	pseudo_bit_t HardwareErrMask[1];
	pseudo_bit_t ResetNegatedMask[1];
};
struct QIB_7322_ErrMask {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_ErrMask_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_ErrStatus_offset 0x00000088UL
struct QIB_7322_ErrStatus_pb {
	pseudo_bit_t _unused_0[12];
	pseudo_bit_t RcvEgrFullErr[1];
	pseudo_bit_t RcvHdrFullErr[1];
	pseudo_bit_t _unused_1[11];
	pseudo_bit_t SDmaBufMaskDuplicateErr[1];
	pseudo_bit_t SDmaWrongPortErr[1];
	pseudo_bit_t SendSpecialTriggerErr[1];
	pseudo_bit_t _unused_2[7];
	pseudo_bit_t SendArmLaunchErr[1];
	pseudo_bit_t SendVLMismatchErr[1];
	pseudo_bit_t _unused_3[15];
	pseudo_bit_t RcvContextShareErr[1];
	pseudo_bit_t InvalidEEPCmdErr[1];
	pseudo_bit_t _unused_4[1];
	pseudo_bit_t SBufVL15MisUseErr[1];
	pseudo_bit_t SDmaVL15Err[1];
	pseudo_bit_t _unused_5[4];
	pseudo_bit_t InvalidAddrErr[1];
	pseudo_bit_t HardwareErr[1];
	pseudo_bit_t ResetNegated[1];
};
struct QIB_7322_ErrStatus {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_ErrStatus_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_ErrClear_offset 0x00000090UL
struct QIB_7322_ErrClear_pb {
	pseudo_bit_t _unused_0[12];
	pseudo_bit_t RcvEgrFullErrClear[1];
	pseudo_bit_t RcvHdrFullErrClear[1];
	pseudo_bit_t _unused_1[11];
	pseudo_bit_t SDmaBufMaskDuplicateErrClear[1];
	pseudo_bit_t SDmaWrongPortErrClear[1];
	pseudo_bit_t SendSpecialTriggerErrClear[1];
	pseudo_bit_t _unused_2[7];
	pseudo_bit_t SendArmLaunchErrClear[1];
	pseudo_bit_t SendVLMismatchErrMask[1];
	pseudo_bit_t _unused_3[15];
	pseudo_bit_t RcvContextShareErrClear[1];
	pseudo_bit_t InvalidEEPCmdErrClear[1];
	pseudo_bit_t _unused_4[1];
	pseudo_bit_t SBufVL15MisUseErrClear[1];
	pseudo_bit_t SDmaVL15ErrClear[1];
	pseudo_bit_t _unused_5[4];
	pseudo_bit_t InvalidAddrErrClear[1];
	pseudo_bit_t HardwareErrClear[1];
	pseudo_bit_t ResetNegatedClear[1];
};
struct QIB_7322_ErrClear {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_ErrClear_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_HwErrMask_offset 0x00000098UL
struct QIB_7322_HwErrMask_pb {
	pseudo_bit_t _unused_0[11];
	pseudo_bit_t LATriggeredMask[1];
	pseudo_bit_t statusValidNoEopMask_0[1];
	pseudo_bit_t IBCBusFromSPCParityErrMask_0[1];
	pseudo_bit_t statusValidNoEopMask_1[1];
	pseudo_bit_t IBCBusFromSPCParityErrMask_1[1];
	pseudo_bit_t _unused_1[11];
	pseudo_bit_t SDmaMemReadErrMask_0[1];
	pseudo_bit_t SDmaMemReadErrMask_1[1];
	pseudo_bit_t PciePoisonedTLPMask[1];
	pseudo_bit_t PcieCplTimeoutMask[1];
	pseudo_bit_t PCIeBusParityErrMask[3];
	pseudo_bit_t pcie_phy_txParityErr[1];
	pseudo_bit_t _unused_2[13];
	pseudo_bit_t MemoryErrMask[1];
	pseudo_bit_t _unused_3[4];
	pseudo_bit_t TempsenseTholdReachedMask[1];
	pseudo_bit_t PowerOnBISTFailedMask[1];
	pseudo_bit_t PCIESerdesPClkNotDetectMask[1];
	pseudo_bit_t _unused_4[6];
	pseudo_bit_t IBSerdesPClkNotDetectMask_0[1];
	pseudo_bit_t IBSerdesPClkNotDetectMask_1[1];
};
struct QIB_7322_HwErrMask {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_HwErrMask_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_HwErrStatus_offset 0x000000a0UL
struct QIB_7322_HwErrStatus_pb {
	pseudo_bit_t _unused_0[11];
	pseudo_bit_t LATriggered[1];
	pseudo_bit_t statusValidNoEop_0[1];
	pseudo_bit_t IBCBusFromSPCParityErr_0[1];
	pseudo_bit_t statusValidNoEop_1[1];
	pseudo_bit_t IBCBusFromSPCParityErr_1[1];
	pseudo_bit_t _unused_1[11];
	pseudo_bit_t SDmaMemReadErr_0[1];
	pseudo_bit_t SDmaMemReadErr_1[1];
	pseudo_bit_t PciePoisonedTLP[1];
	pseudo_bit_t PcieCplTimeout[1];
	pseudo_bit_t PCIeBusParity[3];
	pseudo_bit_t pcie_phy_txParityErr[1];
	pseudo_bit_t _unused_2[13];
	pseudo_bit_t MemoryErr[1];
	pseudo_bit_t _unused_3[4];
	pseudo_bit_t TempsenseTholdReached[1];
	pseudo_bit_t PowerOnBISTFailed[1];
	pseudo_bit_t PCIESerdesPClkNotDetect[1];
	pseudo_bit_t _unused_4[6];
	pseudo_bit_t IBSerdesPClkNotDetect_0[1];
	pseudo_bit_t IBSerdesPClkNotDetect_1[1];
};
struct QIB_7322_HwErrStatus {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_HwErrStatus_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_HwErrClear_offset 0x000000a8UL
struct QIB_7322_HwErrClear_pb {
	pseudo_bit_t _unused_0[11];
	pseudo_bit_t LATriggeredClear[1];
	pseudo_bit_t IBCBusToSPCparityErrClear_0[1];
	pseudo_bit_t IBCBusFromSPCParityErrClear_0[1];
	pseudo_bit_t IBCBusToSPCparityErrClear_1[1];
	pseudo_bit_t IBCBusFromSPCParityErrClear_1[1];
	pseudo_bit_t _unused_1[11];
	pseudo_bit_t SDmaMemReadErrClear_0[1];
	pseudo_bit_t SDmaMemReadErrClear_1[1];
	pseudo_bit_t PciePoisonedTLPClear[1];
	pseudo_bit_t PcieCplTimeoutClear[1];
	pseudo_bit_t PCIeBusParityClear[3];
	pseudo_bit_t pcie_phy_txParityErr[1];
	pseudo_bit_t _unused_2[13];
	pseudo_bit_t MemoryErrClear[1];
	pseudo_bit_t _unused_3[4];
	pseudo_bit_t TempsenseTholdReachedClear[1];
	pseudo_bit_t PowerOnBISTFailedClear[1];
	pseudo_bit_t PCIESerdesPClkNotDetectClear[1];
	pseudo_bit_t _unused_4[6];
	pseudo_bit_t IBSerdesPClkNotDetectClear_0[1];
	pseudo_bit_t IBSerdesPClkNotDetectClear_1[1];
};
struct QIB_7322_HwErrClear {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_HwErrClear_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_HwDiagCtrl_offset 0x000000b0UL
struct QIB_7322_HwDiagCtrl_pb {
	pseudo_bit_t _unused_0[12];
	pseudo_bit_t ForcestatusValidNoEop_0[1];
	pseudo_bit_t ForceIBCBusFromSPCParityErr_0[1];
	pseudo_bit_t ForcestatusValidNoEop_1[1];
	pseudo_bit_t ForceIBCBusFromSPCParityErr_1[1];
	pseudo_bit_t _unused_1[15];
	pseudo_bit_t forcePCIeBusParity[4];
	pseudo_bit_t _unused_2[25];
	pseudo_bit_t CounterDisable[1];
	pseudo_bit_t CounterWrEnable[1];
	pseudo_bit_t _unused_3[1];
	pseudo_bit_t Diagnostic[1];
};
struct QIB_7322_HwDiagCtrl {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_HwDiagCtrl_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_EXTStatus_offset 0x000000c0UL
struct QIB_7322_EXTStatus_pb {
	pseudo_bit_t _unused_0[14];
	pseudo_bit_t MemBISTEndTest[1];
	pseudo_bit_t MemBISTDisabled[1];
	pseudo_bit_t _unused_1[32];
	pseudo_bit_t GPIOIn[16];
};
struct QIB_7322_EXTStatus {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_EXTStatus_pb );
};
/* Default value: 0x000000000000X000 */

#define QIB_7322_EXTCtrl_offset 0x000000c8UL
struct QIB_7322_EXTCtrl_pb {
	pseudo_bit_t LEDPort0YellowOn[1];
	pseudo_bit_t LEDPort0GreenOn[1];
	pseudo_bit_t LEDPort1YellowOn[1];
	pseudo_bit_t LEDPort1GreenOn[1];
	pseudo_bit_t _unused_0[28];
	pseudo_bit_t GPIOInvert[16];
	pseudo_bit_t GPIOOe[16];
};
struct QIB_7322_EXTCtrl {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_EXTCtrl_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_GPIODebugSelReg_offset 0x000000d8UL
struct QIB_7322_GPIODebugSelReg_pb {
	pseudo_bit_t GPIOSourceSelDebug[16];
	pseudo_bit_t SelPulse[16];
	pseudo_bit_t _unused_0[32];
};
struct QIB_7322_GPIODebugSelReg {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_GPIODebugSelReg_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_GPIOOut_offset 0x000000e0UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_GPIOMask_offset 0x000000e8UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_GPIOStatus_offset 0x000000f0UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_GPIOClear_offset 0x000000f8UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvCtrl_offset 0x00000100UL
struct QIB_7322_RcvCtrl_pb {
	pseudo_bit_t dontDropRHQFull[18];
	pseudo_bit_t _unused_0[2];
	pseudo_bit_t IntrAvail[18];
	pseudo_bit_t _unused_1[3];
	pseudo_bit_t ContextCfg[2];
	pseudo_bit_t TidFlowEnable[1];
	pseudo_bit_t XrcTypeCode[3];
	pseudo_bit_t TailUpd[1];
	pseudo_bit_t TidReDirect[16];
};
struct QIB_7322_RcvCtrl {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvCtrl_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvHdrSize_offset 0x00000110UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvHdrCnt_offset 0x00000118UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvHdrEntSize_offset 0x00000120UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvTIDBase_offset 0x00000128UL
/* Default value: 0x0000000000050000 */

#define QIB_7322_RcvTIDCnt_offset 0x00000130UL
/* Default value: 0x0000000000000200 */

#define QIB_7322_RcvEgrBase_offset 0x00000138UL
/* Default value: 0x0000000000014000 */

#define QIB_7322_RcvEgrCnt_offset 0x00000140UL
/* Default value: 0x0000000000001000 */

#define QIB_7322_RcvBufBase_offset 0x00000148UL
/* Default value: 0x0000000000080000 */

#define QIB_7322_RcvBufSize_offset 0x00000150UL
/* Default value: 0x0000000000005000 */

#define QIB_7322_RxIntMemBase_offset 0x00000158UL
/* Default value: 0x0000000000077000 */

#define QIB_7322_RxIntMemSize_offset 0x00000160UL
/* Default value: 0x0000000000007000 */

#define QIB_7322_encryption_key_low_offset 0x00000180UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_encryption_key_high_offset 0x00000188UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_feature_mask_offset 0x00000190UL
/* Default value: 0x00000000000000XX */

#define QIB_7322_active_feature_mask_offset 0x00000198UL
struct QIB_7322_active_feature_mask_pb {
	pseudo_bit_t Port0_SDR_Enabled[1];
	pseudo_bit_t Port0_DDR_Enabled[1];
	pseudo_bit_t Port0_QDR_Enabled[1];
	pseudo_bit_t Port1_SDR_Enabled[1];
	pseudo_bit_t Port1_DDR_Enabled[1];
	pseudo_bit_t Port1_QDR_Enabled[1];
	pseudo_bit_t _unused_0[58];
};
struct QIB_7322_active_feature_mask {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_active_feature_mask_pb );
};
/* Default value: 0x00000000000000XX */

#define QIB_7322_SendCtrl_offset 0x000001c0UL
struct QIB_7322_SendCtrl_pb {
	pseudo_bit_t _unused_0[1];
	pseudo_bit_t SendIntBufAvail[1];
	pseudo_bit_t SendBufAvailUpd[1];
	pseudo_bit_t _unused_1[1];
	pseudo_bit_t SpecialTriggerEn[1];
	pseudo_bit_t _unused_2[11];
	pseudo_bit_t DisarmSendBuf[8];
	pseudo_bit_t AvailUpdThld[5];
	pseudo_bit_t SendBufAvailPad64Byte[1];
	pseudo_bit_t _unused_3[1];
	pseudo_bit_t Disarm[1];
	pseudo_bit_t _unused_4[32];
};
struct QIB_7322_SendCtrl {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SendCtrl_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufBase_offset 0x000001c8UL
struct QIB_7322_SendBufBase_pb {
	pseudo_bit_t BaseAddr_SmallPIO[21];
	pseudo_bit_t _unused_0[11];
	pseudo_bit_t BaseAddr_LargePIO[21];
	pseudo_bit_t _unused_1[11];
};
struct QIB_7322_SendBufBase {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SendBufBase_pb );
};
/* Default value: 0x0018000000100000 */

#define QIB_7322_SendBufSize_offset 0x000001d0UL
struct QIB_7322_SendBufSize_pb {
	pseudo_bit_t Size_SmallPIO[12];
	pseudo_bit_t _unused_0[20];
	pseudo_bit_t Size_LargePIO[13];
	pseudo_bit_t _unused_1[19];
};
struct QIB_7322_SendBufSize {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SendBufSize_pb );
};
/* Default value: 0x0000108000000880 */

#define QIB_7322_SendBufCnt_offset 0x000001d8UL
struct QIB_7322_SendBufCnt_pb {
	pseudo_bit_t Num_SmallBuffers[9];
	pseudo_bit_t _unused_0[23];
	pseudo_bit_t Num_LargeBuffers[6];
	pseudo_bit_t _unused_1[26];
};
struct QIB_7322_SendBufCnt {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SendBufCnt_pb );
};
/* Default value: 0x0000002000000080 */

#define QIB_7322_SendBufAvailAddr_offset 0x000001e0UL
struct QIB_7322_SendBufAvailAddr_pb {
	pseudo_bit_t _unused_0[6];
	pseudo_bit_t SendBufAvailAddr[34];
	pseudo_bit_t _unused_1[24];
};
struct QIB_7322_SendBufAvailAddr {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SendBufAvailAddr_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_TxIntMemBase_offset 0x000001e8UL
/* Default value: 0x0000000000064000 */

#define QIB_7322_TxIntMemSize_offset 0x000001f0UL
/* Default value: 0x000000000000C000 */

#define QIB_7322_SendBufErr0_offset 0x00000240UL
struct QIB_7322_SendBufErr0_pb {
	pseudo_bit_t SendBufErr_63_0[64];
};
struct QIB_7322_SendBufErr0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SendBufErr0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_AvailUpdCount_offset 0x00000268UL
struct QIB_7322_AvailUpdCount_pb {
	pseudo_bit_t AvailUpdCount[5];
	pseudo_bit_t _unused_0[59];
};
struct QIB_7322_AvailUpdCount {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_AvailUpdCount_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvHdrAddr0_offset 0x00000280UL
struct QIB_7322_RcvHdrAddr0_pb {
	pseudo_bit_t _unused_0[2];
	pseudo_bit_t RcvHdrAddr[38];
	pseudo_bit_t _unused_1[24];
};
struct QIB_7322_RcvHdrAddr0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvHdrAddr0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvHdrTailAddr0_offset 0x00000340UL
struct QIB_7322_RcvHdrTailAddr0_pb {
	pseudo_bit_t _unused_0[2];
	pseudo_bit_t RcvHdrTailAddr[38];
	pseudo_bit_t _unused_1[24];
};
struct QIB_7322_RcvHdrTailAddr0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvHdrTailAddr0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_EEPCtlStat_offset 0x000003e8UL
struct QIB_7322_EEPCtlStat_pb {
	pseudo_bit_t EPAccEn[2];
	pseudo_bit_t EPReset[1];
	pseudo_bit_t ByteProg[1];
	pseudo_bit_t PageMode[1];
	pseudo_bit_t LstDatWr[1];
	pseudo_bit_t CmdWrErr[1];
	pseudo_bit_t _unused_0[24];
	pseudo_bit_t CtlrStat[1];
	pseudo_bit_t _unused_1[32];
};
struct QIB_7322_EEPCtlStat {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_EEPCtlStat_pb );
};
/* Default value: 0x0000000000000002 */

#define QIB_7322_EEPAddrCmd_offset 0x000003f0UL
struct QIB_7322_EEPAddrCmd_pb {
	pseudo_bit_t EPAddr[24];
	pseudo_bit_t EPCmd[8];
	pseudo_bit_t _unused_0[32];
};
struct QIB_7322_EEPAddrCmd {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_EEPAddrCmd_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_EEPData_offset 0x000003f8UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_efuse_control_reg_offset 0x00000410UL
struct QIB_7322_efuse_control_reg_pb {
	pseudo_bit_t address[11];
	pseudo_bit_t last_program_address[11];
	pseudo_bit_t operation[2];
	pseudo_bit_t start_operation[1];
	pseudo_bit_t _unused_0[4];
	pseudo_bit_t req_err[1];
	pseudo_bit_t read_data_valid[1];
	pseudo_bit_t rdy[1];
	pseudo_bit_t _unused_1[32];
};
struct QIB_7322_efuse_control_reg {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_efuse_control_reg_pb );
};
/* Default value: 0x0000000080000000 */

#define QIB_7322_efuse_data_reg_offset 0x00000418UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_voltage_margin_reg_offset 0x00000428UL
struct QIB_7322_voltage_margin_reg_pb {
	pseudo_bit_t voltage_margin_settings_enable[1];
	pseudo_bit_t voltage_margin_settings[2];
	pseudo_bit_t _unused_0[61];
};
struct QIB_7322_voltage_margin_reg {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_voltage_margin_reg_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_VTSense_reg_offset 0x00000430UL
struct QIB_7322_VTSense_reg_pb {
	pseudo_bit_t temp_sense_select[3];
	pseudo_bit_t adc_mode[1];
	pseudo_bit_t start_busy[1];
	pseudo_bit_t power_down[1];
	pseudo_bit_t threshold[10];
	pseudo_bit_t sensor_output_data[10];
	pseudo_bit_t _unused_0[1];
	pseudo_bit_t threshold_limbit[1];
	pseudo_bit_t _unused_1[3];
	pseudo_bit_t output_valid[1];
	pseudo_bit_t _unused_2[32];
};
struct QIB_7322_VTSense_reg {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_VTSense_reg_pb );
};
/* Default value: 0x0000000000000020 */

#define QIB_7322_procmon_reg_offset 0x00000438UL
struct QIB_7322_procmon_reg_pb {
	pseudo_bit_t ring_osc_select[3];
	pseudo_bit_t _unused_0[12];
	pseudo_bit_t start_counter[1];
	pseudo_bit_t procmon_count[12];
	pseudo_bit_t _unused_1[3];
	pseudo_bit_t procmon_count_valid[1];
	pseudo_bit_t _unused_2[32];
};
struct QIB_7322_procmon_reg {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_procmon_reg_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_PcieRbufTestReg0_offset 0x00000440UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_ahb_access_ctrl_offset 0x00000460UL
struct QIB_7322_ahb_access_ctrl_pb {
	pseudo_bit_t sw_ahb_sel[1];
	pseudo_bit_t sw_sel_ahb_trgt[2];
	pseudo_bit_t _unused_0[61];
};
struct QIB_7322_ahb_access_ctrl {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_ahb_access_ctrl_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_ahb_transaction_reg_offset 0x00000468UL
struct QIB_7322_ahb_transaction_reg_pb {
	pseudo_bit_t _unused_0[16];
	pseudo_bit_t ahb_address[11];
	pseudo_bit_t write_not_read[1];
	pseudo_bit_t _unused_1[2];
	pseudo_bit_t ahb_req_err[1];
	pseudo_bit_t ahb_rdy[1];
	pseudo_bit_t ahb_data[32];
};
struct QIB_7322_ahb_transaction_reg {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_ahb_transaction_reg_pb );
};
/* Default value: 0x0000000080000000 */

#define QIB_7322_SPC_JTAG_ACCESS_REG_offset 0x00000470UL
struct QIB_7322_SPC_JTAG_ACCESS_REG_pb {
	pseudo_bit_t rdy[1];
	pseudo_bit_t tdo[1];
	pseudo_bit_t tdi[1];
	pseudo_bit_t opcode[2];
	pseudo_bit_t bist_en[5];
	pseudo_bit_t SPC_JTAG_ACCESS_EN[1];
	pseudo_bit_t _unused_0[53];
};
struct QIB_7322_SPC_JTAG_ACCESS_REG {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SPC_JTAG_ACCESS_REG_pb );
};
/* Default value: 0x0000000000000001 */

#define QIB_7322_LAControlReg_offset 0x00000478UL
struct QIB_7322_LAControlReg_pb {
	pseudo_bit_t Finished[1];
	pseudo_bit_t Address[9];
	pseudo_bit_t Mode[2];
	pseudo_bit_t Delay[20];
	pseudo_bit_t Finished_sc[1];
	pseudo_bit_t Address_sc[9];
	pseudo_bit_t Mode_sc[2];
	pseudo_bit_t Delay_sc[20];
};
struct QIB_7322_LAControlReg {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_LAControlReg_pb );
};
/* Default value: 0x0000000100000001 */

#define QIB_7322_PcieRhdrTestReg0_offset 0x00000480UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendCheckMask0_offset 0x000004c0UL
struct QIB_7322_SendCheckMask0_pb {
	pseudo_bit_t SendCheckMask_63_32[64];
};
struct QIB_7322_SendCheckMask0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SendCheckMask0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendGRHCheckMask0_offset 0x000004e0UL
struct QIB_7322_SendGRHCheckMask0_pb {
	pseudo_bit_t SendGRHCheckMask_63_32[64];
};
struct QIB_7322_SendGRHCheckMask0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SendGRHCheckMask0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendIBPacketMask0_offset 0x00000500UL
struct QIB_7322_SendIBPacketMask0_pb {
	pseudo_bit_t SendIBPacketMask_63_32[64];
};
struct QIB_7322_SendIBPacketMask0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SendIBPacketMask0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_IntRedirect0_offset 0x00000540UL
struct QIB_7322_IntRedirect0_pb {
	pseudo_bit_t vec0[5];
	pseudo_bit_t vec1[5];
	pseudo_bit_t vec2[5];
	pseudo_bit_t vec3[5];
	pseudo_bit_t vec4[5];
	pseudo_bit_t vec5[5];
	pseudo_bit_t vec6[5];
	pseudo_bit_t vec7[5];
	pseudo_bit_t vec8[5];
	pseudo_bit_t vec9[5];
	pseudo_bit_t vec10[5];
	pseudo_bit_t vec11[5];
	pseudo_bit_t _unused_0[4];
};
struct QIB_7322_IntRedirect0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_IntRedirect0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_Int_Granted_offset 0x00000570UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_vec_clr_without_int_offset 0x00000578UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_DCACtrlA_offset 0x00000580UL
struct QIB_7322_DCACtrlA_pb {
	pseudo_bit_t RcvHdrqDCAEnable[1];
	pseudo_bit_t EagerDCAEnable[1];
	pseudo_bit_t RcvTailUpdDCAEnable[1];
	pseudo_bit_t SendDMAHead0DCAEnable[1];
	pseudo_bit_t SendDMAHead1DCAEnable[1];
	pseudo_bit_t _unused_0[59];
};
struct QIB_7322_DCACtrlA {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_DCACtrlA_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_DCACtrlB_offset 0x00000588UL
struct QIB_7322_DCACtrlB_pb {
	pseudo_bit_t RcvHdrq0DCAOPH[8];
	pseudo_bit_t RcvHdrq0DCAXfrCnt[6];
	pseudo_bit_t RcvHdrq1DCAOPH[8];
	pseudo_bit_t RcvHdrq1DCAXfrCnt[6];
	pseudo_bit_t _unused_0[4];
	pseudo_bit_t RcvHdrq2DCAOPH[8];
	pseudo_bit_t RcvHdrq2DCAXfrCnt[6];
	pseudo_bit_t RcvHdrq3DCAOPH[8];
	pseudo_bit_t RcvHdrq3DCAXfrCnt[6];
	pseudo_bit_t _unused_1[4];
};
struct QIB_7322_DCACtrlB {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_DCACtrlB_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_DCACtrlC_offset 0x00000590UL
struct QIB_7322_DCACtrlC_pb {
	pseudo_bit_t RcvHdrq4DCAOPH[8];
	pseudo_bit_t RcvHdrq4DCAXfrCnt[6];
	pseudo_bit_t RcvHdrq5DCAOPH[8];
	pseudo_bit_t RcvHdrq5DCAXfrCnt[6];
	pseudo_bit_t _unused_0[4];
	pseudo_bit_t RcvHdrq6DCAOPH[8];
	pseudo_bit_t RcvHdrq6DCAXfrCnt[6];
	pseudo_bit_t RcvHdrq7DCAOPH[8];
	pseudo_bit_t RcvHdrq7DCAXfrCnt[6];
	pseudo_bit_t _unused_1[4];
};
struct QIB_7322_DCACtrlC {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_DCACtrlC_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_DCACtrlD_offset 0x00000598UL
struct QIB_7322_DCACtrlD_pb {
	pseudo_bit_t RcvHdrq8DCAOPH[8];
	pseudo_bit_t RcvHdrq8DCAXfrCnt[6];
	pseudo_bit_t RcvHdrq9DCAOPH[8];
	pseudo_bit_t RcvHdrq9DCAXfrCnt[6];
	pseudo_bit_t _unused_0[4];
	pseudo_bit_t RcvHdrq10DCAOPH[8];
	pseudo_bit_t RcvHdrq10DCAXfrCnt[6];
	pseudo_bit_t RcvHdrq11DCAOPH[8];
	pseudo_bit_t RcvHdrq11DCAXfrCnt[6];
	pseudo_bit_t _unused_1[4];
};
struct QIB_7322_DCACtrlD {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_DCACtrlD_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_DCACtrlE_offset 0x000005a0UL
struct QIB_7322_DCACtrlE_pb {
	pseudo_bit_t RcvHdrq12DCAOPH[8];
	pseudo_bit_t RcvHdrq12DCAXfrCnt[6];
	pseudo_bit_t RcvHdrq13DCAOPH[8];
	pseudo_bit_t RcvHdrq13DCAXfrCnt[6];
	pseudo_bit_t _unused_0[4];
	pseudo_bit_t RcvHdrq14DCAOPH[8];
	pseudo_bit_t RcvHdrq14DCAXfrCnt[6];
	pseudo_bit_t RcvHdrq15DCAOPH[8];
	pseudo_bit_t RcvHdrq15DCAXfrCnt[6];
	pseudo_bit_t _unused_1[4];
};
struct QIB_7322_DCACtrlE {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_DCACtrlE_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_DCACtrlF_offset 0x000005a8UL
struct QIB_7322_DCACtrlF_pb {
	pseudo_bit_t RcvHdrq16DCAOPH[8];
	pseudo_bit_t RcvHdrq16DCAXfrCnt[6];
	pseudo_bit_t RcvHdrq17DCAOPH[8];
	pseudo_bit_t RcvHdrq17DCAXfrCnt[6];
	pseudo_bit_t _unused_0[4];
	pseudo_bit_t SendDma0DCAOPH[8];
	pseudo_bit_t SendDma1DCAOPH[8];
	pseudo_bit_t _unused_1[16];
};
struct QIB_7322_DCACtrlF {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_DCACtrlF_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_MemErrCtrlA_offset 0x00000600UL
struct QIB_7322_MemErrCtrlA_pb {
	pseudo_bit_t FSSUncErrRcvBuf_0[1];
	pseudo_bit_t FSSUncErrRcvFlags_0[1];
	pseudo_bit_t FSSUncErrLookupiqBuf_0[1];
	pseudo_bit_t FSSUncErrRcvDMAHdrBuf_0[1];
	pseudo_bit_t FSSUncErrRcvDMADataBuf_0[1];
	pseudo_bit_t FSSUncErrRcvBuf_1[1];
	pseudo_bit_t FSSUncErrRcvFlags_1[1];
	pseudo_bit_t FSSUncErrLookupiqBuf_1[1];
	pseudo_bit_t FSSUncErrRcvDMAHdrBuf_1[1];
	pseudo_bit_t FSSUncErrRcvDMADataBuf_1[1];
	pseudo_bit_t FSSUncErrRcvTIDArray[1];
	pseudo_bit_t FSSUncErrRcvEgrArray[1];
	pseudo_bit_t _unused_0[3];
	pseudo_bit_t FSSUncErrSendBufVL15[1];
	pseudo_bit_t FSSUncErrSendBufMain[1];
	pseudo_bit_t FSSUncErrSendBufExtra[1];
	pseudo_bit_t FSSUncErrSendPbcArray[1];
	pseudo_bit_t FSSUncErrSendLaFIFO0_0[1];
	pseudo_bit_t FSSUncErrSendLaFIFO1_0[1];
	pseudo_bit_t FSSUncErrSendLaFIFO2_0[1];
	pseudo_bit_t FSSUncErrSendLaFIFO3_0[1];
	pseudo_bit_t FSSUncErrSendLaFIFO4_0[1];
	pseudo_bit_t FSSUncErrSendLaFIFO5_0[1];
	pseudo_bit_t FSSUncErrSendLaFIFO6_0[1];
	pseudo_bit_t FSSUncErrSendLaFIFO7_0[1];
	pseudo_bit_t FSSUncErrSendLaFIFO0_1[1];
	pseudo_bit_t FSSUncErrSendLaFIFO1_1[1];
	pseudo_bit_t FSSUncErrSendLaFIFO2_1[1];
	pseudo_bit_t FSSUncErrSendLaFIFO3_1[1];
	pseudo_bit_t FSSUncErrSendLaFIFO4_1[1];
	pseudo_bit_t FSSUncErrSendLaFIFO5_1[1];
	pseudo_bit_t FSSUncErrSendLaFIFO6_1[1];
	pseudo_bit_t FSSUncErrSendLaFIFO7_1[1];
	pseudo_bit_t FSSUncErrSendRmFIFO_0[1];
	pseudo_bit_t FSSUncErrSendRmFIFO_1[1];
	pseudo_bit_t _unused_1[11];
	pseudo_bit_t FSSUncErrPCIeRetryBuf[1];
	pseudo_bit_t FSSUncErrPCIePostHdrBuf[1];
	pseudo_bit_t FSSUncErrPCIePostDataBuf[1];
	pseudo_bit_t FSSUncErrPCIeCompHdrBuf[1];
	pseudo_bit_t FSSUncErrPCIeCompDataBuf[1];
	pseudo_bit_t FSSUncErrMsixTable0[1];
	pseudo_bit_t FSSUncErrMsixTable1[1];
	pseudo_bit_t FSSUncErrMsixTable2[1];
	pseudo_bit_t _unused_2[4];
	pseudo_bit_t SwapEccDataMsixBits[1];
	pseudo_bit_t SwapEccDataExtraBits[1];
	pseudo_bit_t DisableEccCorrection[1];
	pseudo_bit_t SwapEccDataBits[1];
};
struct QIB_7322_MemErrCtrlA {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_MemErrCtrlA_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_MemErrCtrlB_offset 0x00000608UL
struct QIB_7322_MemErrCtrlB_pb {
	pseudo_bit_t FSSCorErrRcvBuf_0[1];
	pseudo_bit_t FSSCorErrRcvFlags_0[1];
	pseudo_bit_t FSSCorErrLookupiqBuf_0[1];
	pseudo_bit_t FSSCorErrRcvDMAHdrBuf_0[1];
	pseudo_bit_t FSSCorErrRcvDMADataBuf_0[1];
	pseudo_bit_t FSSCorErrRcvBuf_1[1];
	pseudo_bit_t FSSCorErrRcvFlags_1[1];
	pseudo_bit_t FSSCorErrLookupiqBuf_1[1];
	pseudo_bit_t FSSCorErrRcvDMAHdrBuf_1[1];
	pseudo_bit_t FSSCorErrRcvDMADataBuf_1[1];
	pseudo_bit_t FSSCorErrRcvTIDArray[1];
	pseudo_bit_t FSSCorErrRcvEgrArray[1];
	pseudo_bit_t _unused_0[3];
	pseudo_bit_t FSSCorErrSendBufVL15[1];
	pseudo_bit_t FSSCorErrSendBufMain[1];
	pseudo_bit_t FSSCorErrSendBufExtra[1];
	pseudo_bit_t FSSCorErrSendPbcArray[1];
	pseudo_bit_t FSSCorErrSendLaFIFO0_0[1];
	pseudo_bit_t FSSCorErrSendLaFIFO1_0[1];
	pseudo_bit_t FSSCorErrSendLaFIFO2_0[1];
	pseudo_bit_t FSSCorErrSendLaFIFO3_0[1];
	pseudo_bit_t FSSCorErrSendLaFIFO4_0[1];
	pseudo_bit_t FSSCorErrSendLaFIFO5_0[1];
	pseudo_bit_t FSSCorErrSendLaFIFO6_0[1];
	pseudo_bit_t FSSCorErrSendLaFIFO7_0[1];
	pseudo_bit_t FSSCorErrSendLaFIFO0_1[1];
	pseudo_bit_t FSSCorErrSendLaFIFO1_1[1];
	pseudo_bit_t FSSCorErrSendLaFIFO2_1[1];
	pseudo_bit_t FSSCorErrSendLaFIFO3_1[1];
	pseudo_bit_t FSSCorErrSendLaFIFO4_1[1];
	pseudo_bit_t FSSCorErrSendLaFIFO5_1[1];
	pseudo_bit_t FSSCorErrSendLaFIFO6_1[1];
	pseudo_bit_t FSSCorErrSendLaFIFO7_1[1];
	pseudo_bit_t FSSCorErrSendRmFIFO_0[1];
	pseudo_bit_t FSSCorErrSendRmFIFO_1[1];
	pseudo_bit_t _unused_1[11];
	pseudo_bit_t FSSCorErrPCIeRetryBuf[1];
	pseudo_bit_t FSSCorErrPCIePostHdrBuf[1];
	pseudo_bit_t FSSCorErrPCIePostDataBuf[1];
	pseudo_bit_t FSSCorErrPCIeCompHdrBuf[1];
	pseudo_bit_t FSSCorErrPCIeCompDataBuf[1];
	pseudo_bit_t FSSCorErrMsixTable0[1];
	pseudo_bit_t FSSCorErrMsixTable1[1];
	pseudo_bit_t FSSCorErrMsixTable2[1];
	pseudo_bit_t _unused_2[8];
};
struct QIB_7322_MemErrCtrlB {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_MemErrCtrlB_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_MemMultiUnCorErrMask_offset 0x00000610UL
struct QIB_7322_MemMultiUnCorErrMask_pb {
	pseudo_bit_t MulUncErrMskRcvBuf_0[1];
	pseudo_bit_t MulUncErrMskRcvFlags_0[1];
	pseudo_bit_t MulUncErrMskLookupiqBuf_0[1];
	pseudo_bit_t MulUncErrMskRcvDMAHdrBuf_0[1];
	pseudo_bit_t MulUncErrMskRcvDMADataBuf_0[1];
	pseudo_bit_t MulUncErrMskRcvBuf_1[1];
	pseudo_bit_t MulUncErrMskRcvFlags_1[1];
	pseudo_bit_t MulUncErrMskLookupiqBuf_1[1];
	pseudo_bit_t MulUncErrMskRcvDMAHdrBuf_1[1];
	pseudo_bit_t MulUncErrMskRcvDMADataBuf_1[1];
	pseudo_bit_t MulUncErrMskRcvTIDArray[1];
	pseudo_bit_t MulUncErrMskRcvEgrArray[1];
	pseudo_bit_t _unused_0[3];
	pseudo_bit_t MulUncErrMskSendBufVL15[1];
	pseudo_bit_t MulUncErrMskSendBufMain[1];
	pseudo_bit_t MulUncErrMskSendBufExtra[1];
	pseudo_bit_t MulUncErrMskSendPbcArray[1];
	pseudo_bit_t MulUncErrMskSendLaFIFO0_0[1];
	pseudo_bit_t MulUncErrMskSendLaFIFO1_0[1];
	pseudo_bit_t MulUncErrMskSendLaFIFO2_0[1];
	pseudo_bit_t MulUncErrMskSendLaFIFO3_0[1];
	pseudo_bit_t MulUncErrMskSendLaFIFO4_0[1];
	pseudo_bit_t MulUncErrMskSendLaFIFO5_0[1];
	pseudo_bit_t MulUncErrMskSendLaFIFO6_0[1];
	pseudo_bit_t MulUncErrMskSendLaFIFO7_0[1];
	pseudo_bit_t MulUncErrMskSendLaFIFO0_1[1];
	pseudo_bit_t MulUncErrMskSendLaFIFO1_1[1];
	pseudo_bit_t MulUncErrMskSendLaFIFO2_1[1];
	pseudo_bit_t MulUncErrMskSendLaFIFO3_1[1];
	pseudo_bit_t MulUncErrMskSendLaFIFO4_1[1];
	pseudo_bit_t MulUncErrMskSendLaFIFO5_1[1];
	pseudo_bit_t MulUncErrMskSendLaFIFO6_1[1];
	pseudo_bit_t MulUncErrMskSendLaFIFO7_1[1];
	pseudo_bit_t MulUncErrMskSendRmFIFO_0[1];
	pseudo_bit_t MulUncErrMskSendRmFIFO_1[1];
	pseudo_bit_t _unused_1[11];
	pseudo_bit_t MulUncErrMskPCIeRetryBuf[1];
	pseudo_bit_t MulUncErrMskPCIePostHdrBuf[1];
	pseudo_bit_t MulUncErrMskPCIePostDataBuf[1];
	pseudo_bit_t MulUncErrMskPCIeCompHdrBuf[1];
	pseudo_bit_t MulUncErrMskPCIeCompDataBuf[1];
	pseudo_bit_t MulUncErrMskMsixTable0[1];
	pseudo_bit_t MulUncErrMskMsixTable1[1];
	pseudo_bit_t MulUncErrMskMsixTable2[1];
	pseudo_bit_t _unused_2[8];
};
struct QIB_7322_MemMultiUnCorErrMask {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_MemMultiUnCorErrMask_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_MemMultiUnCorErrStatus_offset 0x00000618UL
struct QIB_7322_MemMultiUnCorErrStatus_pb {
	pseudo_bit_t MulUncErrStatusRcvBuf_0[1];
	pseudo_bit_t MulUncErrStatusRcvFlags_0[1];
	pseudo_bit_t MulUncErrStatusLookupiqBuf_0[1];
	pseudo_bit_t MulUncErrStatusRcvDMAHdrBuf_0[1];
	pseudo_bit_t MulUncErrStatusRcvDMADataBuf_0[1];
	pseudo_bit_t MulUncErrStatusRcvBuf_1[1];
	pseudo_bit_t MulUncErrStatusRcvFlags_1[1];
	pseudo_bit_t MulUncErrStatusLookupiqBuf_1[1];
	pseudo_bit_t MulUncErrStatusRcvDMAHdrBuf_1[1];
	pseudo_bit_t MulUncErrStatusRcvDMADataBuf_1[1];
	pseudo_bit_t MulUncErrStatusRcvTIDArray[1];
	pseudo_bit_t MulUncErrStatusRcvEgrArray[1];
	pseudo_bit_t _unused_0[3];
	pseudo_bit_t MulUncErrStatusSendBufVL15[1];
	pseudo_bit_t MulUncErrStatusSendBufMain[1];
	pseudo_bit_t MulUncErrStatusSendBufExtra[1];
	pseudo_bit_t MulUncErrStatusSendPbcArray[1];
	pseudo_bit_t MulUncErrStatusSendLaFIFO0_0[1];
	pseudo_bit_t MulUncErrStatusSendLaFIFO1_0[1];
	pseudo_bit_t MulUncErrStatusSendLaFIFO2_0[1];
	pseudo_bit_t MulUncErrStatusSendLaFIFO3_0[1];
	pseudo_bit_t MulUncErrStatusSendLaFIFO4_0[1];
	pseudo_bit_t MulUncErrStatusSendLaFIFO5_0[1];
	pseudo_bit_t MulUncErrStatusSendLaFIFO6_0[1];
	pseudo_bit_t MulUncErrStatusSendLaFIFO7_0[1];
	pseudo_bit_t MulUncErrStatusSendLaFIFO0_1[1];
	pseudo_bit_t MulUncErrStatusSendLaFIFO1_1[1];
	pseudo_bit_t MulUncErrStatusSendLaFIFO2_1[1];
	pseudo_bit_t MulUncErrStatusSendLaFIFO3_1[1];
	pseudo_bit_t MulUncErrStatusSendLaFIFO4_1[1];
	pseudo_bit_t MulUncErrStatusSendLaFIFO5_1[1];
	pseudo_bit_t MulUncErrStatusSendLaFIFO6_1[1];
	pseudo_bit_t MulUncErrStatusSendLaFIFO7_1[1];
	pseudo_bit_t MulUncErrStatusSendRmFIFO_0[1];
	pseudo_bit_t MulUncErrStatusSendRmFIFO_1[1];
	pseudo_bit_t _unused_1[11];
	pseudo_bit_t MulUncErrStatusPCIeRetryBuf[1];
	pseudo_bit_t MulUncErrStatusPCIePostHdrBuf[1];
	pseudo_bit_t MulUncErrStatusPCIePostDataBuf[1];
	pseudo_bit_t MulUncErrStatusPCIeCompHdrBuf[1];
	pseudo_bit_t MulUncErrStatusPCIeCompDataBuf[1];
	pseudo_bit_t MulUncErrStatusMsixTable0[1];
	pseudo_bit_t MulUncErrStatusMsixTable1[1];
	pseudo_bit_t MulUncErrStatusMsixTable2[1];
	pseudo_bit_t _unused_2[8];
};
struct QIB_7322_MemMultiUnCorErrStatus {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_MemMultiUnCorErrStatus_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_MemMultiUnCorErrClear_offset 0x00000620UL
struct QIB_7322_MemMultiUnCorErrClear_pb {
	pseudo_bit_t MulUncErrClearRcvBuf_0[1];
	pseudo_bit_t MulUncErrClearRcvFlags_0[1];
	pseudo_bit_t MulUncErrClearLookupiqBuf_0[1];
	pseudo_bit_t MulUncErrClearRcvDMAHdrBuf_0[1];
	pseudo_bit_t MulUncErrClearRcvDMADataBuf_0[1];
	pseudo_bit_t MulUncErrClearRcvBuf_1[1];
	pseudo_bit_t MulUncErrClearRcvFlags_1[1];
	pseudo_bit_t MulUncErrClearLookupiqBuf_1[1];
	pseudo_bit_t MulUncErrClearRcvDMAHdrBuf_1[1];
	pseudo_bit_t MulUncErrClearRcvDMADataBuf_1[1];
	pseudo_bit_t MulUncErrClearRcvTIDArray[1];
	pseudo_bit_t MulUncErrClearRcvEgrArray[1];
	pseudo_bit_t _unused_0[3];
	pseudo_bit_t MulUncErrClearSendBufVL15[1];
	pseudo_bit_t MulUncErrClearSendBufMain[1];
	pseudo_bit_t MulUncErrClearSendBufExtra[1];
	pseudo_bit_t MulUncErrClearSendPbcArray[1];
	pseudo_bit_t MulUncErrClearSendLaFIFO0_0[1];
	pseudo_bit_t MulUncErrClearSendLaFIFO1_0[1];
	pseudo_bit_t MulUncErrClearSendLaFIFO2_0[1];
	pseudo_bit_t MulUncErrClearSendLaFIFO3_0[1];
	pseudo_bit_t MulUncErrClearSendLaFIFO4_0[1];
	pseudo_bit_t MulUncErrClearSendLaFIFO5_0[1];
	pseudo_bit_t MulUncErrClearSendLaFIFO6_0[1];
	pseudo_bit_t MulUncErrClearSendLaFIFO7_0[1];
	pseudo_bit_t MulUncErrClearSendLaFIFO0_1[1];
	pseudo_bit_t MulUncErrClearSendLaFIFO1_1[1];
	pseudo_bit_t MulUncErrClearSendLaFIFO2_1[1];
	pseudo_bit_t MulUncErrClearSendLaFIFO3_1[1];
	pseudo_bit_t MulUncErrClearSendLaFIFO4_1[1];
	pseudo_bit_t MulUncErrClearSendLaFIFO5_1[1];
	pseudo_bit_t MulUncErrClearSendLaFIFO6_1[1];
	pseudo_bit_t MulUncErrClearSendLaFIFO7_1[1];
	pseudo_bit_t MulUncErrClearSendRmFIFO_0[1];
	pseudo_bit_t MulUncErrClearSendRmFIFO_1[1];
	pseudo_bit_t _unused_1[11];
	pseudo_bit_t MulUncErrClearPCIeRetryBuf[1];
	pseudo_bit_t MulUncErrClearPCIePostHdrBuf[1];
	pseudo_bit_t MulUncErrClearPCIePostDataBuf[1];
	pseudo_bit_t MulUncErrClearPCIeCompHdrBuf[1];
	pseudo_bit_t MulUncErrClearPCIeCompDataBuf[1];
	pseudo_bit_t MulUncErrClearMsixTable0[1];
	pseudo_bit_t MulUncErrClearMsixTable1[1];
	pseudo_bit_t MulUncErrClearMsixTable2[1];
	pseudo_bit_t _unused_2[8];
};
struct QIB_7322_MemMultiUnCorErrClear {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_MemMultiUnCorErrClear_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_MemUnCorErrMask_offset 0x00000628UL
struct QIB_7322_MemUnCorErrMask_pb {
	pseudo_bit_t UncErrMskRcvBuf_0[1];
	pseudo_bit_t UncErrMskRcvFlags_0[1];
	pseudo_bit_t UncErrMskLookupiqBuf_0[1];
	pseudo_bit_t UncErrMskRcvDMAHdrBuf_0[1];
	pseudo_bit_t UncErrMskRcvDMADataBuf_0[1];
	pseudo_bit_t UncErrMskRcvBuf_1[1];
	pseudo_bit_t UncErrMskRcvFlags_1[1];
	pseudo_bit_t UncErrMskLookupiqBuf_1[1];
	pseudo_bit_t UncErrMskRcvDMAHdrBuf_1[1];
	pseudo_bit_t UncErrMskRcvDMADataBuf_1[1];
	pseudo_bit_t UncErrMskRcvTIDArray[1];
	pseudo_bit_t UncErrMskRcvEgrArray[1];
	pseudo_bit_t _unused_0[3];
	pseudo_bit_t UncErrMskSendBufVL15[1];
	pseudo_bit_t UncErrMskSendBufMain[1];
	pseudo_bit_t UncErrMskSendBufExtra[1];
	pseudo_bit_t UncErrMskSendPbcArray[1];
	pseudo_bit_t UncErrMskSendLaFIFO0_0[1];
	pseudo_bit_t UncErrMskSendLaFIFO1_0[1];
	pseudo_bit_t UncErrMskSendLaFIFO2_0[1];
	pseudo_bit_t UncErrMskSendLaFIFO3_0[1];
	pseudo_bit_t UncErrMskSendLaFIFO4_0[1];
	pseudo_bit_t UncErrMskSendLaFIFO5_0[1];
	pseudo_bit_t UncErrMskSendLaFIFO6_0[1];
	pseudo_bit_t UncErrMskSendLaFIFO7_0[1];
	pseudo_bit_t UncErrMskSendLaFIFO0_1[1];
	pseudo_bit_t UncErrMskSendLaFIFO1_1[1];
	pseudo_bit_t UncErrMskSendLaFIFO2_1[1];
	pseudo_bit_t UncErrMskSendLaFIFO3_1[1];
	pseudo_bit_t UncErrMskSendLaFIFO4_1[1];
	pseudo_bit_t UncErrMskSendLaFIFO5_1[1];
	pseudo_bit_t UncErrMskSendLaFIFO6_1[1];
	pseudo_bit_t UncErrMskSendLaFIFO7_1[1];
	pseudo_bit_t UncErrMskSendRmFIFO_0[1];
	pseudo_bit_t UncErrMskSendRmFIFO_1[1];
	pseudo_bit_t _unused_1[11];
	pseudo_bit_t UncErrMskPCIeRetryBuf[1];
	pseudo_bit_t UncErrMskPCIePostHdrBuf[1];
	pseudo_bit_t UncErrMskPCIePostDataBuf[1];
	pseudo_bit_t UncErrMskPCIeCompHdrBuf[1];
	pseudo_bit_t UncErrMskPCIeCompDataBuf[1];
	pseudo_bit_t UncErrMskMsixTable0[1];
	pseudo_bit_t UncErrMskMsixTable1[1];
	pseudo_bit_t UncErrMskMsixTable2[1];
	pseudo_bit_t _unused_2[8];
};
struct QIB_7322_MemUnCorErrMask {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_MemUnCorErrMask_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_MemUnCorErrStatus_offset 0x00000630UL
struct QIB_7322_MemUnCorErrStatus_pb {
	pseudo_bit_t UncErrStatusRcvBuf_0[1];
	pseudo_bit_t UncErrStatusRcvFlags_0[1];
	pseudo_bit_t UncErrStatusLookupiqBuf_0[1];
	pseudo_bit_t UncErrStatusRcvDMAHdrBuf_0[1];
	pseudo_bit_t UncErrStatusRcvDMADataBuf_0[1];
	pseudo_bit_t UncErrStatusRcvBuf_1[1];
	pseudo_bit_t UncErrStatusRcvFlags_1[1];
	pseudo_bit_t UncErrStatusLookupiqBuf_1[1];
	pseudo_bit_t UncErrStatusRcvDMAHdrBuf_1[1];
	pseudo_bit_t UncErrStatusRcvDMADataBuf_1[1];
	pseudo_bit_t UncErrStatusRcvTIDArray[1];
	pseudo_bit_t UncErrStatusRcvEgrArray[1];
	pseudo_bit_t _unused_0[3];
	pseudo_bit_t UncErrStatusSendBufVL15[1];
	pseudo_bit_t UncErrStatusSendBufMain[1];
	pseudo_bit_t UncErrStatusSendBufExtra[1];
	pseudo_bit_t UncErrStatusSendPbcArray[1];
	pseudo_bit_t UncErrStatusSendLaFIFO0_0[1];
	pseudo_bit_t UncErrStatusSendLaFIFO1_0[1];
	pseudo_bit_t UncErrStatusSendLaFIFO2_0[1];
	pseudo_bit_t UncErrStatusSendLaFIFO3_0[1];
	pseudo_bit_t UncErrStatusSendLaFIFO4_0[1];
	pseudo_bit_t UncErrStatusSendLaFIFO5_0[1];
	pseudo_bit_t UncErrStatusSendLaFIFO6_0[1];
	pseudo_bit_t UncErrStatusSendLaFIFO7_0[1];
	pseudo_bit_t UncErrStatusSendLaFIFO0_1[1];
	pseudo_bit_t UncErrStatusSendLaFIFO1_1[1];
	pseudo_bit_t UncErrStatusSendLaFIFO2_1[1];
	pseudo_bit_t UncErrStatusSendLaFIFO3_1[1];
	pseudo_bit_t UncErrStatusSendLaFIFO4_1[1];
	pseudo_bit_t UncErrStatusSendLaFIFO5_1[1];
	pseudo_bit_t UncErrStatusSendLaFIFO6_1[1];
	pseudo_bit_t UncErrStatusSendLaFIFO7_1[1];
	pseudo_bit_t UncErrStatusSendRmFIFO_0[1];
	pseudo_bit_t UncErrStatusSendRmFIFO_1[1];
	pseudo_bit_t _unused_1[11];
	pseudo_bit_t UncErrStatusPCIeRetryBuf[1];
	pseudo_bit_t UncErrStatusPCIePostHdrBuf[1];
	pseudo_bit_t UncErrStatusPCIePostDataBuf[1];
	pseudo_bit_t UncErrStatusPCIeCompHdrBuf[1];
	pseudo_bit_t UncErrStatusPCIeCompDataBuf[1];
	pseudo_bit_t UncErrStatusMsixTable0[1];
	pseudo_bit_t UncErrStatusMsixTable1[1];
	pseudo_bit_t UncErrStatusMsixTable2[1];
	pseudo_bit_t _unused_2[8];
};
struct QIB_7322_MemUnCorErrStatus {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_MemUnCorErrStatus_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_MemUnCorErrClear_offset 0x00000638UL
struct QIB_7322_MemUnCorErrClear_pb {
	pseudo_bit_t UncErrClearRcvBuf_0[1];
	pseudo_bit_t UncErrClearRcvFlags_0[1];
	pseudo_bit_t UncErrClearLookupiqBuf_0[1];
	pseudo_bit_t UncErrClearRcvDMAHdrBuf_0[1];
	pseudo_bit_t UncErrClearRcvDMADataBuf_0[1];
	pseudo_bit_t UncErrClearRcvBuf_1[1];
	pseudo_bit_t UncErrClearRcvFlags_1[1];
	pseudo_bit_t UncErrClearLookupiqBuf_1[1];
	pseudo_bit_t UncErrClearRcvDMAHdrBuf_1[1];
	pseudo_bit_t UncErrClearRcvDMADataBuf_1[1];
	pseudo_bit_t UncErrClearRcvTIDArray[1];
	pseudo_bit_t UncErrClearRcvEgrArray[1];
	pseudo_bit_t _unused_0[3];
	pseudo_bit_t UncErrClearSendBufVL15[1];
	pseudo_bit_t UncErrClearSendBufMain[1];
	pseudo_bit_t UncErrClearSendBufExtra[1];
	pseudo_bit_t UncErrClearSendPbcArray[1];
	pseudo_bit_t UncErrClearSendLaFIFO0_0[1];
	pseudo_bit_t UncErrClearSendLaFIFO1_0[1];
	pseudo_bit_t UncErrClearSendLaFIFO2_0[1];
	pseudo_bit_t UncErrClearSendLaFIFO3_0[1];
	pseudo_bit_t UncErrClearSendLaFIFO4_0[1];
	pseudo_bit_t UncErrClearSendLaFIFO5_0[1];
	pseudo_bit_t UncErrClearSendLaFIFO6_0[1];
	pseudo_bit_t UncErrClearSendLaFIFO7_0[1];
	pseudo_bit_t UncErrClearSendLaFIFO0_1[1];
	pseudo_bit_t UncErrClearSendLaFIFO1_1[1];
	pseudo_bit_t UncErrClearSendLaFIFO2_1[1];
	pseudo_bit_t UncErrClearSendLaFIFO3_1[1];
	pseudo_bit_t UncErrClearSendLaFIFO4_1[1];
	pseudo_bit_t UncErrClearSendLaFIFO5_1[1];
	pseudo_bit_t UncErrClearSendLaFIFO6_1[1];
	pseudo_bit_t UncErrClearSendLaFIFO7_1[1];
	pseudo_bit_t UncErrClearSendRmFIFO_0[1];
	pseudo_bit_t UncErrClearSendRmFIFO_1[1];
	pseudo_bit_t _unused_1[11];
	pseudo_bit_t UncErrClearPCIeRetryBuf[1];
	pseudo_bit_t UncErrClearPCIePostHdrBuf[1];
	pseudo_bit_t UncErrClearPCIePostDataBuf[1];
	pseudo_bit_t UncErrClearPCIeCompHdrBuf[1];
	pseudo_bit_t UncErrClearPCIeCompDataBuf[1];
	pseudo_bit_t UncErrClearMsixTable0[1];
	pseudo_bit_t UncErrClearMsixTable1[1];
	pseudo_bit_t UncErrClearMsixTable2[1];
	pseudo_bit_t _unused_2[8];
};
struct QIB_7322_MemUnCorErrClear {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_MemUnCorErrClear_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_MemMultiCorErrMask_offset 0x00000640UL
struct QIB_7322_MemMultiCorErrMask_pb {
	pseudo_bit_t MulCorErrMskRcvBuf_0[1];
	pseudo_bit_t MulCorErrMskRcvFlags_0[1];
	pseudo_bit_t MulCorErrMskLookupiqBuf_0[1];
	pseudo_bit_t MulCorErrMskRcvDMAHdrBuf_0[1];
	pseudo_bit_t MulCorErrMskRcvDMADataBuf_0[1];
	pseudo_bit_t MulCorErrMskRcvBuf_1[1];
	pseudo_bit_t MulCorErrMskRcvFlags_1[1];
	pseudo_bit_t MulCorErrMskLookupiqBuf_1[1];
	pseudo_bit_t MulCorErrMskRcvDMAHdrBuf_1[1];
	pseudo_bit_t MulCorErrMskRcvDMADataBuf_1[1];
	pseudo_bit_t MulCorErrMskRcvTIDArray[1];
	pseudo_bit_t MulCorErrMskRcvEgrArray[1];
	pseudo_bit_t _unused_0[3];
	pseudo_bit_t MulCorErrMskSendBufVL15[1];
	pseudo_bit_t MulCorErrMskSendBufMain[1];
	pseudo_bit_t MulCorErrMskSendBufExtra[1];
	pseudo_bit_t MulCorErrMskSendPbcArray[1];
	pseudo_bit_t MulCorErrMskSendLaFIFO0_0[1];
	pseudo_bit_t MulCorErrMskSendLaFIFO1_0[1];
	pseudo_bit_t MulCorErrMskSendLaFIFO2_0[1];
	pseudo_bit_t MulCorErrMskSendLaFIFO3_0[1];
	pseudo_bit_t MulCorErrMskSendLaFIFO4_0[1];
	pseudo_bit_t MulCorErrMskSendLaFIFO5_0[1];
	pseudo_bit_t MulCorErrMskSendLaFIFO6_0[1];
	pseudo_bit_t MulCorErrMskSendLaFIFO7_0[1];
	pseudo_bit_t MulCorErrMskSendLaFIFO0_1[1];
	pseudo_bit_t MulCorErrMskSendLaFIFO1_1[1];
	pseudo_bit_t MulCorErrMskSendLaFIFO2_1[1];
	pseudo_bit_t MulCorErrMskSendLaFIFO3_1[1];
	pseudo_bit_t MulCorErrMskSendLaFIFO4_1[1];
	pseudo_bit_t MulCorErrMskSendLaFIFO5_1[1];
	pseudo_bit_t MulCorErrMskSendLaFIFO6_1[1];
	pseudo_bit_t MulCorErrMskSendLaFIFO7_1[1];
	pseudo_bit_t MulCorErrMskSendRmFIFO_0[1];
	pseudo_bit_t MulCorErrMskSendRmFIFO_1[1];
	pseudo_bit_t _unused_1[11];
	pseudo_bit_t MulCorErrMskPCIeRetryBuf[1];
	pseudo_bit_t MulCorErrMskPCIePostHdrBuf[1];
	pseudo_bit_t MulCorErrMskPCIePostDataBuf[1];
	pseudo_bit_t MulCorErrMskPCIeCompHdrBuf[1];
	pseudo_bit_t MulCorErrMskPCIeCompDataBuf[1];
	pseudo_bit_t MulCorErrMskMsixTable0[1];
	pseudo_bit_t MulCorErrMskMsixTable1[1];
	pseudo_bit_t MulCorErrMskMsixTable2[1];
	pseudo_bit_t _unused_2[8];
};
struct QIB_7322_MemMultiCorErrMask {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_MemMultiCorErrMask_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_MemMultiCorErrStatus_offset 0x00000648UL
struct QIB_7322_MemMultiCorErrStatus_pb {
	pseudo_bit_t MulCorErrStatusRcvBuf_0[1];
	pseudo_bit_t MulCorErrStatusRcvFlags_0[1];
	pseudo_bit_t MulCorErrStatusLookupiqBuf_0[1];
	pseudo_bit_t MulCorErrStatusRcvDMAHdrBuf_0[1];
	pseudo_bit_t MulCorErrStatusRcvDMADataBuf_0[1];
	pseudo_bit_t MulCorErrStatusRcvBuf_1[1];
	pseudo_bit_t MulCorErrStatusRcvFlags_1[1];
	pseudo_bit_t MulCorErrStatusLookupiqBuf_1[1];
	pseudo_bit_t MulCorErrStatusRcvDMAHdrBuf_1[1];
	pseudo_bit_t MulCorErrStatusRcvDMADataBuf_1[1];
	pseudo_bit_t MulCorErrStatusRcvTIDArray[1];
	pseudo_bit_t MulCorErrStatusRcvEgrArray[1];
	pseudo_bit_t _unused_0[3];
	pseudo_bit_t MulCorErrStatusSendBufVL15[1];
	pseudo_bit_t MulCorErrStatusSendBufMain[1];
	pseudo_bit_t MulCorErrStatusSendBufExtra[1];
	pseudo_bit_t MulCorErrStatusSendPbcArray[1];
	pseudo_bit_t MulCorErrStatusSendLaFIFO0_0[1];
	pseudo_bit_t MulCorErrStatusSendLaFIFO1_0[1];
	pseudo_bit_t MulCorErrStatusSendLaFIFO2_0[1];
	pseudo_bit_t MulCorErrStatusSendLaFIFO3_0[1];
	pseudo_bit_t MulCorErrStatusSendLaFIFO4_0[1];
	pseudo_bit_t MulCorErrStatusSendLaFIFO5_0[1];
	pseudo_bit_t MulCorErrStatusSendLaFIFO6_0[1];
	pseudo_bit_t MulCorErrStatusSendLaFIFO7_0[1];
	pseudo_bit_t MulCorErrStatusSendLaFIFO0_1[1];
	pseudo_bit_t MulCorErrStatusSendLaFIFO1_1[1];
	pseudo_bit_t MulCorErrStatusSendLaFIFO2_1[1];
	pseudo_bit_t MulCorErrStatusSendLaFIFO3_1[1];
	pseudo_bit_t MulCorErrStatusSendLaFIFO4_1[1];
	pseudo_bit_t MulCorErrStatusSendLaFIFO5_1[1];
	pseudo_bit_t MulCorErrStatusSendLaFIFO6_1[1];
	pseudo_bit_t MulCorErrStatusSendLaFIFO7_1[1];
	pseudo_bit_t MulCorErrStatusSendRmFIFO_0[1];
	pseudo_bit_t MulCorErrStatusSendRmFIFO_1[1];
	pseudo_bit_t _unused_1[11];
	pseudo_bit_t MulCorErrStatusPCIeRetryBuf[1];
	pseudo_bit_t MulCorErrStatusPCIePostHdrBuf[1];
	pseudo_bit_t MulCorErrStatusPCIePostDataBuf[1];
	pseudo_bit_t MulCorErrStatusPCIeCompHdrBuf[1];
	pseudo_bit_t MulCorErrStatusPCIeCompDataBuf[1];
	pseudo_bit_t MulCorErrStatusMsixTable0[1];
	pseudo_bit_t MulCorErrStatusMsixTable1[1];
	pseudo_bit_t MulCorErrStatusMsixTable2[1];
	pseudo_bit_t _unused_2[8];
};
struct QIB_7322_MemMultiCorErrStatus {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_MemMultiCorErrStatus_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_MemMultiCorErrClear_offset 0x00000650UL
struct QIB_7322_MemMultiCorErrClear_pb {
	pseudo_bit_t MulCorErrClearRcvBuf_0[1];
	pseudo_bit_t MulCorErrClearRcvFlags_0[1];
	pseudo_bit_t MulCorErrClearLookupiqBuf_0[1];
	pseudo_bit_t MulCorErrClearRcvDMAHdrBuf_0[1];
	pseudo_bit_t MulCorErrClearRcvDMADataBuf_0[1];
	pseudo_bit_t MulCorErrClearRcvBuf_1[1];
	pseudo_bit_t MulCorErrClearRcvFlags_1[1];
	pseudo_bit_t MulCorErrClearLookupiqBuf_1[1];
	pseudo_bit_t MulCorErrClearRcvDMAHdrBuf_1[1];
	pseudo_bit_t MulCorErrClearRcvDMADataBuf_1[1];
	pseudo_bit_t MulCorErrClearRcvTIDArray[1];
	pseudo_bit_t MulCorErrClearRcvEgrArray[1];
	pseudo_bit_t _unused_0[3];
	pseudo_bit_t MulCorErrClearSendBufVL15[1];
	pseudo_bit_t MulCorErrClearSendBufMain[1];
	pseudo_bit_t MulCorErrClearSendBufExtra[1];
	pseudo_bit_t MulCorErrClearSendPbcArray[1];
	pseudo_bit_t MulCorErrClearSendLaFIFO0_0[1];
	pseudo_bit_t MulCorErrClearSendLaFIFO1_0[1];
	pseudo_bit_t MulCorErrClearSendLaFIFO2_0[1];
	pseudo_bit_t MulCorErrClearSendLaFIFO3_0[1];
	pseudo_bit_t MulCorErrClearSendLaFIFO4_0[1];
	pseudo_bit_t MulCorErrClearSendLaFIFO5_0[1];
	pseudo_bit_t MulCorErrClearSendLaFIFO6_0[1];
	pseudo_bit_t MulCorErrClearSendLaFIFO7_0[1];
	pseudo_bit_t MulCorErrClearSendLaFIFO0_1[1];
	pseudo_bit_t MulCorErrClearSendLaFIFO1_1[1];
	pseudo_bit_t MulCorErrClearSendLaFIFO2_1[1];
	pseudo_bit_t MulCorErrClearSendLaFIFO3_1[1];
	pseudo_bit_t MulCorErrClearSendLaFIFO4_1[1];
	pseudo_bit_t MulCorErrClearSendLaFIFO5_1[1];
	pseudo_bit_t MulCorErrClearSendLaFIFO6_1[1];
	pseudo_bit_t MulCorErrClearSendLaFIFO7_1[1];
	pseudo_bit_t MulCorErrClearSendRmFIFO_0[1];
	pseudo_bit_t MulCorErrClearSendRmFIFO_1[1];
	pseudo_bit_t _unused_1[11];
	pseudo_bit_t MulCorErrClearPCIeRetryBuf[1];
	pseudo_bit_t MulCorErrClearPCIePostHdrBuf[1];
	pseudo_bit_t MulCorErrClearPCIePostDataBuf[1];
	pseudo_bit_t MulCorErrClearPCIeCompHdrBuf[1];
	pseudo_bit_t MulCorErrClearPCIeCompDataBuf[1];
	pseudo_bit_t MulCorErrClearMsixTable0[1];
	pseudo_bit_t MulCorErrClearMsixTable1[1];
	pseudo_bit_t MulCorErrClearMsixTable2[1];
	pseudo_bit_t _unused_2[8];
};
struct QIB_7322_MemMultiCorErrClear {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_MemMultiCorErrClear_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_MemCorErrMask_offset 0x00000658UL
struct QIB_7322_MemCorErrMask_pb {
	pseudo_bit_t CorErrMskRcvBuf_0[1];
	pseudo_bit_t CorErrMskRcvFlags_0[1];
	pseudo_bit_t CorErrMskLookupiqBuf_0[1];
	pseudo_bit_t CorErrMskRcvDMAHdrBuf_0[1];
	pseudo_bit_t CorErrMskRcvDMADataBuf_0[1];
	pseudo_bit_t CorErrMskRcvBuf_1[1];
	pseudo_bit_t CorErrMskRcvFlags_1[1];
	pseudo_bit_t CorErrMskLookupiqBuf_1[1];
	pseudo_bit_t CorErrMskRcvDMAHdrBuf_1[1];
	pseudo_bit_t CorErrMskRcvDMADataBuf_1[1];
	pseudo_bit_t CorErrMskRcvTIDArray[1];
	pseudo_bit_t CorErrMskRcvEgrArray[1];
	pseudo_bit_t _unused_0[3];
	pseudo_bit_t CorErrMskSendBufVL15[1];
	pseudo_bit_t CorErrMskSendBufMain[1];
	pseudo_bit_t CorErrMskSendBufExtra[1];
	pseudo_bit_t CorErrMskSendPbcArray[1];
	pseudo_bit_t CorErrMskSendLaFIFO0_0[1];
	pseudo_bit_t CorErrMskSendLaFIFO1_0[1];
	pseudo_bit_t CorErrMskSendLaFIFO2_0[1];
	pseudo_bit_t CorErrMskSendLaFIFO3_0[1];
	pseudo_bit_t CorErrMskSendLaFIFO4_0[1];
	pseudo_bit_t CorErrMskSendLaFIFO5_0[1];
	pseudo_bit_t CorErrMskSendLaFIFO6_0[1];
	pseudo_bit_t CorErrMskSendLaFIFO7_0[1];
	pseudo_bit_t CorErrMskSendLaFIFO0_1[1];
	pseudo_bit_t CorErrMskSendLaFIFO1_1[1];
	pseudo_bit_t CorErrMskSendLaFIFO2_1[1];
	pseudo_bit_t CorErrMskSendLaFIFO3_1[1];
	pseudo_bit_t CorErrMskSendLaFIFO4_1[1];
	pseudo_bit_t CorErrMskSendLaFIFO5_1[1];
	pseudo_bit_t CorErrMskSendLaFIFO6_1[1];
	pseudo_bit_t CorErrMskSendLaFIFO7_1[1];
	pseudo_bit_t CorErrMskSendRmFIFO_0[1];
	pseudo_bit_t CorErrMskSendRmFIFO_1[1];
	pseudo_bit_t _unused_1[11];
	pseudo_bit_t CorErrMskPCIeRetryBuf[1];
	pseudo_bit_t CorErrMskPCIePostHdrBuf[1];
	pseudo_bit_t CorErrMskPCIePostDataBuf[1];
	pseudo_bit_t CorErrMskPCIeCompHdrBuf[1];
	pseudo_bit_t CorErrMskPCIeCompDataBuf[1];
	pseudo_bit_t CorErrMskMsixTable0[1];
	pseudo_bit_t CorErrMskMsixTable1[1];
	pseudo_bit_t CorErrMskMsixTable2[1];
	pseudo_bit_t _unused_2[8];
};
struct QIB_7322_MemCorErrMask {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_MemCorErrMask_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_MemCorErrStatus_offset 0x00000660UL
struct QIB_7322_MemCorErrStatus_pb {
	pseudo_bit_t CorErrStatusRcvBuf_0[1];
	pseudo_bit_t CorErrStatusRcvFlags_0[1];
	pseudo_bit_t CorErrStatusLookupiqBuf_0[1];
	pseudo_bit_t CorErrStatusRcvDMAHdrBuf_0[1];
	pseudo_bit_t CorErrStatusRcvDMADataBuf_0[1];
	pseudo_bit_t CorErrStatusRcvBuf_1[1];
	pseudo_bit_t CorErrStatusRcvFlags_1[1];
	pseudo_bit_t CorErrStatusLookupiqBuf_1[1];
	pseudo_bit_t CorErrStatusRcvDMAHdrBuf_1[1];
	pseudo_bit_t CorErrStatusRcvDMADataBuf_1[1];
	pseudo_bit_t CorErrStatusRcvTIDArray[1];
	pseudo_bit_t CorErrStatusRcvEgrArray[1];
	pseudo_bit_t _unused_0[3];
	pseudo_bit_t CorErrStatusSendBufVL15[1];
	pseudo_bit_t CorErrStatusSendBufMain[1];
	pseudo_bit_t CorErrStatusSendBufExtra[1];
	pseudo_bit_t CorErrStatusSendPbcArray[1];
	pseudo_bit_t CorErrStatusSendLaFIFO0_0[1];
	pseudo_bit_t CorErrStatusSendLaFIFO1_0[1];
	pseudo_bit_t CorErrStatusSendLaFIFO2_0[1];
	pseudo_bit_t CorErrStatusSendLaFIFO3_0[1];
	pseudo_bit_t CorErrStatusSendLaFIFO4_0[1];
	pseudo_bit_t CorErrStatusSendLaFIFO5_0[1];
	pseudo_bit_t CorErrStatusSendLaFIFO6_0[1];
	pseudo_bit_t CorErrStatusSendLaFIFO7_0[1];
	pseudo_bit_t CorErrStatusSendLaFIFO0_1[1];
	pseudo_bit_t CorErrStatusSendLaFIFO1_1[1];
	pseudo_bit_t CorErrStatusSendLaFIFO2_1[1];
	pseudo_bit_t CorErrStatusSendLaFIFO3_1[1];
	pseudo_bit_t CorErrStatusSendLaFIFO4_1[1];
	pseudo_bit_t CorErrStatusSendLaFIFO5_1[1];
	pseudo_bit_t CorErrStatusSendLaFIFO6_1[1];
	pseudo_bit_t CorErrStatusSendLaFIFO7_1[1];
	pseudo_bit_t CorErrStatusSendRmFIFO_0[1];
	pseudo_bit_t CorErrStatusSendRmFIFO_1[1];
	pseudo_bit_t _unused_1[11];
	pseudo_bit_t CorErrStatusPCIeRetryBuf[1];
	pseudo_bit_t CorErrStatusPCIePostHdrBuf[1];
	pseudo_bit_t CorErrStatusPCIePostDataBuf[1];
	pseudo_bit_t CorErrStatusPCIeCompHdrBuf[1];
	pseudo_bit_t CorErrStatusPCIeCompDataBuf[1];
	pseudo_bit_t CorErrStatusMsixTable0[1];
	pseudo_bit_t CorErrStatusMsixTable1[1];
	pseudo_bit_t CorErrStatusMsixTable2[1];
	pseudo_bit_t _unused_2[8];
};
struct QIB_7322_MemCorErrStatus {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_MemCorErrStatus_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_MemCorErrClear_offset 0x00000668UL
struct QIB_7322_MemCorErrClear_pb {
	pseudo_bit_t CorErrClearRcvBuf_0[1];
	pseudo_bit_t CorErrClearRcvFlags_0[1];
	pseudo_bit_t CorErrClearLookupiqBuf_0[1];
	pseudo_bit_t CorErrClearRcvDMAHdrBuf_0[1];
	pseudo_bit_t CorErrClearRcvDMADataBuf_0[1];
	pseudo_bit_t CorErrClearRcvBuf_1[1];
	pseudo_bit_t CorErrClearRcvFlags_1[1];
	pseudo_bit_t CorErrClearLookupiqBuf_1[1];
	pseudo_bit_t CorErrClearRcvDMAHdrBuf_1[1];
	pseudo_bit_t CorErrClearRcvDMADataBuf_1[1];
	pseudo_bit_t CorErrClearRcvTIDArray[1];
	pseudo_bit_t CorErrClearRcvEgrArray[1];
	pseudo_bit_t _unused_0[3];
	pseudo_bit_t CorErrClearSendBufVL15[1];
	pseudo_bit_t CorErrClearSendBufMain[1];
	pseudo_bit_t CorErrClearSendBufExtra[1];
	pseudo_bit_t CorErrClearSendPbcArray[1];
	pseudo_bit_t CorErrClearSendLaFIFO0_0[1];
	pseudo_bit_t CorErrClearSendLaFIFO1_0[1];
	pseudo_bit_t CorErrClearSendLaFIFO2_0[1];
	pseudo_bit_t CorErrClearSendLaFIFO3_0[1];
	pseudo_bit_t CorErrClearSendLaFIFO4_0[1];
	pseudo_bit_t CorErrClearSendLaFIFO5_0[1];
	pseudo_bit_t CorErrClearSendLaFIFO6_0[1];
	pseudo_bit_t CorErrClearSendLaFIFO7_0[1];
	pseudo_bit_t CorErrClearSendLaFIFO0_1[1];
	pseudo_bit_t CorErrClearSendLaFIFO1_1[1];
	pseudo_bit_t CorErrClearSendLaFIFO2_1[1];
	pseudo_bit_t CorErrClearSendLaFIFO3_1[1];
	pseudo_bit_t CorErrClearSendLaFIFO4_1[1];
	pseudo_bit_t CorErrClearSendLaFIFO5_1[1];
	pseudo_bit_t CorErrClearSendLaFIFO6_1[1];
	pseudo_bit_t CorErrClearSendLaFIFO7_1[1];
	pseudo_bit_t CorErrClearSendRmFIFO_0[1];
	pseudo_bit_t CorErrClearSendRmFIFO_1[1];
	pseudo_bit_t _unused_1[11];
	pseudo_bit_t CorErrClearPCIeRetryBuf[1];
	pseudo_bit_t CorErrClearPCIePostHdrBuf[1];
	pseudo_bit_t CorErrClearPCIePostDataBuf[1];
	pseudo_bit_t CorErrClearPCIeCompHdrBuf[1];
	pseudo_bit_t CorErrClearPCIeCompDataBuf[1];
	pseudo_bit_t CorErrClearMsixTable0[1];
	pseudo_bit_t CorErrClearMsixTable1[1];
	pseudo_bit_t CorErrClearMsixTable2[1];
	pseudo_bit_t _unused_2[8];
};
struct QIB_7322_MemCorErrClear {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_MemCorErrClear_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_MsixTableUnCorErrLogA_offset 0x00000680UL
struct QIB_7322_MsixTableUnCorErrLogA_pb {
	pseudo_bit_t MsixTable_1_0_UnCorErrData[64];
};
struct QIB_7322_MsixTableUnCorErrLogA {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_MsixTableUnCorErrLogA_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_MsixTableUnCorErrLogB_offset 0x00000688UL
struct QIB_7322_MsixTableUnCorErrLogB_pb {
	pseudo_bit_t MsixTable_2_UnCorErrData[32];
	pseudo_bit_t MsixTable_0_UnCorErrCheckBits[7];
	pseudo_bit_t MsixTable_1_UnCorErrCheckBits[7];
	pseudo_bit_t MsixTable_2_UnCorErrCheckBits[7];
	pseudo_bit_t _unused_0[11];
};
struct QIB_7322_MsixTableUnCorErrLogB {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_MsixTableUnCorErrLogB_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_MsixTableUnCorErrLogC_offset 0x00000690UL
struct QIB_7322_MsixTableUnCorErrLogC_pb {
	pseudo_bit_t MsixTable_0_UnCorErrAddr[7];
	pseudo_bit_t MsixTable_1_UnCorErrAddr[7];
	pseudo_bit_t MsixTable_2_UnCorErrAddr[7];
	pseudo_bit_t _unused_0[43];
};
struct QIB_7322_MsixTableUnCorErrLogC {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_MsixTableUnCorErrLogC_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_MsixEntryWithUncorErr_offset 0x00000698UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_MsixTableCorErrLogA_offset 0x000006a0UL
struct QIB_7322_MsixTableCorErrLogA_pb {
	pseudo_bit_t MsixTable_1_0_CorErrData[64];
};
struct QIB_7322_MsixTableCorErrLogA {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_MsixTableCorErrLogA_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_MsixTableCorErrLogB_offset 0x000006a8UL
struct QIB_7322_MsixTableCorErrLogB_pb {
	pseudo_bit_t MsixTable_2_CorErrData[32];
	pseudo_bit_t MsixTable_0_CorErrCheckBits[7];
	pseudo_bit_t MsixTable_1_CorErrCheckBits[7];
	pseudo_bit_t MsixTable_2_CorErrCheckBits[7];
	pseudo_bit_t _unused_0[11];
};
struct QIB_7322_MsixTableCorErrLogB {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_MsixTableCorErrLogB_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_MsixTableCorErrLogC_offset 0x000006b0UL
struct QIB_7322_MsixTableCorErrLogC_pb {
	pseudo_bit_t MsixTable_0_CorErrAddr[7];
	pseudo_bit_t MsixTable_1_CorErrAddr[7];
	pseudo_bit_t MsixTable_2_CorErrAddr[7];
	pseudo_bit_t _unused_0[43];
};
struct QIB_7322_MsixTableCorErrLogC {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_MsixTableCorErrLogC_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_PcieCplDataBufrUnCorErrLogA_offset 0x00000700UL
struct QIB_7322_PcieCplDataBufrUnCorErrLogA_pb {
	pseudo_bit_t PcieCplDataBufrUnCorErrData_63_0[64];
};
struct QIB_7322_PcieCplDataBufrUnCorErrLogA {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_PcieCplDataBufrUnCorErrLogA_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_PcieCplDataBufrUnCorErrLogB_offset 0x00000708UL
struct QIB_7322_PcieCplDataBufrUnCorErrLogB_pb {
	pseudo_bit_t PcieCplDataBufrUnCorErrData_127_64[64];
};
struct QIB_7322_PcieCplDataBufrUnCorErrLogB {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_PcieCplDataBufrUnCorErrLogB_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_PcieCplDataBufrUnCorErrLogC_offset 0x00000710UL
struct QIB_7322_PcieCplDataBufrUnCorErrLogC_pb {
	pseudo_bit_t PcieCplDataBufrUnCorErrData_136_128[9];
	pseudo_bit_t PcieCplDataBufrUnCorErrCheckBit_21_0[22];
	pseudo_bit_t PcieCplDataBufrUnCorErrAddr_13_0[14];
	pseudo_bit_t _unused_0[19];
};
struct QIB_7322_PcieCplDataBufrUnCorErrLogC {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_PcieCplDataBufrUnCorErrLogC_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_PcieCplHdrBufrUnCorErrLogA_offset 0x00000720UL
struct QIB_7322_PcieCplHdrBufrUnCorErrLogA_pb {
	pseudo_bit_t PcieCplHdrBufrUnCorErrHdr_63_0[64];
};
struct QIB_7322_PcieCplHdrBufrUnCorErrLogA {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_PcieCplHdrBufrUnCorErrLogA_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_PcieCplHdrBufrUnCorErrLogB_offset 0x00000728UL
struct QIB_7322_PcieCplHdrBufrUnCorErrLogB_pb {
	pseudo_bit_t PcieCplHdrBufrUnCorErrHdr_103_64[40];
	pseudo_bit_t _unused_0[24];
};
struct QIB_7322_PcieCplHdrBufrUnCorErrLogB {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_PcieCplHdrBufrUnCorErrLogB_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_PcieCplHdrBufrUnCorErrLogC_offset 0x00000730UL
struct QIB_7322_PcieCplHdrBufrUnCorErrLogC_pb {
	pseudo_bit_t PcieCplHdrBufrUnCorErrCheckBit_15_0[16];
	pseudo_bit_t PcieCplHdrBufrUnCorErrAddr_8_0[9];
	pseudo_bit_t _unused_0[39];
};
struct QIB_7322_PcieCplHdrBufrUnCorErrLogC {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_PcieCplHdrBufrUnCorErrLogC_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_PciePDataBufrUnCorErrLogA_offset 0x00000740UL
struct QIB_7322_PciePDataBufrUnCorErrLogA_pb {
	pseudo_bit_t PciePDataBufrUnCorErrData_63_0[64];
};
struct QIB_7322_PciePDataBufrUnCorErrLogA {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_PciePDataBufrUnCorErrLogA_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_PciePDataBufrUnCorErrLogB_offset 0x00000748UL
struct QIB_7322_PciePDataBufrUnCorErrLogB_pb {
	pseudo_bit_t PciePDataBufrUnCorErrData_127_64[64];
};
struct QIB_7322_PciePDataBufrUnCorErrLogB {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_PciePDataBufrUnCorErrLogB_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_PciePDataBufrUnCorErrLogC_offset 0x00000750UL
struct QIB_7322_PciePDataBufrUnCorErrLogC_pb {
	pseudo_bit_t PciePDataBufrUnCorErrData_136_128[9];
	pseudo_bit_t PciePDataBufrUnCorErrCheckBit_21_0[22];
	pseudo_bit_t PciePDataBufrUnCorErrAddr_13_0[14];
	pseudo_bit_t _unused_0[19];
};
struct QIB_7322_PciePDataBufrUnCorErrLogC {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_PciePDataBufrUnCorErrLogC_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_PciePHdrBufrUnCorErrLogA_offset 0x00000760UL
struct QIB_7322_PciePHdrBufrUnCorErrLogA_pb {
	pseudo_bit_t PciePHdrBufrUnCorErrData_63_0[64];
};
struct QIB_7322_PciePHdrBufrUnCorErrLogA {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_PciePHdrBufrUnCorErrLogA_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_PciePHdrBufrUnCorErrLogB_offset 0x00000768UL
struct QIB_7322_PciePHdrBufrUnCorErrLogB_pb {
	pseudo_bit_t PciePHdrBufrUnCorErrData_107_64[44];
	pseudo_bit_t _unused_0[20];
};
struct QIB_7322_PciePHdrBufrUnCorErrLogB {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_PciePHdrBufrUnCorErrLogB_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_PciePHdrBufrUnCorErrLogC_offset 0x00000770UL
struct QIB_7322_PciePHdrBufrUnCorErrLogC_pb {
	pseudo_bit_t PciePHdrBufrUnCorErrCheckBit_15_0[16];
	pseudo_bit_t PciePHdrBufrUnCorErrAddr_8_0[9];
	pseudo_bit_t _unused_0[39];
};
struct QIB_7322_PciePHdrBufrUnCorErrLogC {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_PciePHdrBufrUnCorErrLogC_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_PcieRetryBufrUnCorErrLogA_offset 0x00000780UL
struct QIB_7322_PcieRetryBufrUnCorErrLogA_pb {
	pseudo_bit_t PcieRetryBufrUnCorErrData_63_0[64];
};
struct QIB_7322_PcieRetryBufrUnCorErrLogA {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_PcieRetryBufrUnCorErrLogA_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_PcieRetryBufrUnCorErrLogB_offset 0x00000788UL
struct QIB_7322_PcieRetryBufrUnCorErrLogB_pb {
	pseudo_bit_t PcieRetryBufrUnCorErrData_127_64[64];
};
struct QIB_7322_PcieRetryBufrUnCorErrLogB {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_PcieRetryBufrUnCorErrLogB_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_PcieRetryBufrUnCorErrLogC_offset 0x00000790UL
struct QIB_7322_PcieRetryBufrUnCorErrLogC_pb {
	pseudo_bit_t PcieRetryBufrUnCorErrData_133_128[6];
	pseudo_bit_t PcieRetryBufrUnCorErrCheckBit_20_0[21];
	pseudo_bit_t PcieRetryBufrUnCorErrAddr_13_0[14];
	pseudo_bit_t _unused_0[23];
};
struct QIB_7322_PcieRetryBufrUnCorErrLogC {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_PcieRetryBufrUnCorErrLogC_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxTIDArrayUnCorErrLogA_offset 0x00000800UL
struct QIB_7322_RxTIDArrayUnCorErrLogA_pb {
	pseudo_bit_t RxTIDArrayUnCorErrData_39_0[40];
	pseudo_bit_t RxTIDArrayUnCorErrCheckBit_11_0[12];
	pseudo_bit_t _unused_0[12];
};
struct QIB_7322_RxTIDArrayUnCorErrLogA {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxTIDArrayUnCorErrLogA_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxTIDArrayUnCorErrLogB_offset 0x00000808UL
struct QIB_7322_RxTIDArrayUnCorErrLogB_pb {
	pseudo_bit_t RxTIDArrayUnCorErrAddr_16_0[17];
	pseudo_bit_t _unused_0[47];
};
struct QIB_7322_RxTIDArrayUnCorErrLogB {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxTIDArrayUnCorErrLogB_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxEagerArrayUnCorErrLogA_offset 0x00000810UL
struct QIB_7322_RxEagerArrayUnCorErrLogA_pb {
	pseudo_bit_t RxEagerArrayUnCorErrData_39_0[40];
	pseudo_bit_t RxEagerArrayUnCorErrCheckBit_11_0[12];
	pseudo_bit_t _unused_0[12];
};
struct QIB_7322_RxEagerArrayUnCorErrLogA {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxEagerArrayUnCorErrLogA_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxEagerArrayUnCorErrLogB_offset 0x00000818UL
struct QIB_7322_RxEagerArrayUnCorErrLogB_pb {
	pseudo_bit_t RxEagerArrayUnCorErrAddr_17_0[18];
	pseudo_bit_t _unused_0[46];
};
struct QIB_7322_RxEagerArrayUnCorErrLogB {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxEagerArrayUnCorErrLogB_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_SBufMainArrayUnCorErrLogA_offset 0x00000880UL
struct QIB_7322_SBufMainArrayUnCorErrLogA_pb {
	pseudo_bit_t SBufMainArrayUnCorErrData_63_0[64];
};
struct QIB_7322_SBufMainArrayUnCorErrLogA {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SBufMainArrayUnCorErrLogA_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_SBufMainArrayUnCorErrLogB_offset 0x00000888UL
struct QIB_7322_SBufMainArrayUnCorErrLogB_pb {
	pseudo_bit_t SBufMainArrayUnCorErrData_127_64[64];
};
struct QIB_7322_SBufMainArrayUnCorErrLogB {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SBufMainArrayUnCorErrLogB_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_SBufMainArrayUnCorErrLogC_offset 0x00000890UL
struct QIB_7322_SBufMainArrayUnCorErrLogC_pb {
	pseudo_bit_t SBufMainArrayUnCorErrCheckBit_27_0[28];
	pseudo_bit_t SBufMainArrayUnCorErrAddr_18_0[19];
	pseudo_bit_t _unused_0[13];
	pseudo_bit_t SBufMainArrayUnCorErrDword_3_0[4];
};
struct QIB_7322_SBufMainArrayUnCorErrLogC {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SBufMainArrayUnCorErrLogC_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_SBufExtraArrayUnCorErrLogA_offset 0x00000898UL
struct QIB_7322_SBufExtraArrayUnCorErrLogA_pb {
	pseudo_bit_t SBufExtraArrayUnCorErrData_63_0[64];
};
struct QIB_7322_SBufExtraArrayUnCorErrLogA {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SBufExtraArrayUnCorErrLogA_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_SBufExtraArrayUnCorErrLogB_offset 0x000008a0UL
struct QIB_7322_SBufExtraArrayUnCorErrLogB_pb {
	pseudo_bit_t SBufExtraArrayUnCorErrData_127_64[64];
};
struct QIB_7322_SBufExtraArrayUnCorErrLogB {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SBufExtraArrayUnCorErrLogB_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_SBufExtraArrayUnCorErrLogC_offset 0x000008a8UL
struct QIB_7322_SBufExtraArrayUnCorErrLogC_pb {
	pseudo_bit_t SBufExtraArrayUnCorErrCheckBit_27_0[28];
	pseudo_bit_t SBufExtraArrayUnCorErrAddr_14_0[15];
	pseudo_bit_t _unused_0[17];
	pseudo_bit_t SBufExtraArrayUnCorErrAdd_3_0[4];
};
struct QIB_7322_SBufExtraArrayUnCorErrLogC {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SBufExtraArrayUnCorErrLogC_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendPbcArrayUnCorErrLog_offset 0x000008b0UL
struct QIB_7322_SendPbcArrayUnCorErrLog_pb {
	pseudo_bit_t SendPbcArrayUnCorErrData_21_0[22];
	pseudo_bit_t SendPbcArrayUnCorErrCheckBit_6_0[7];
	pseudo_bit_t SendPbcArrayUnCorErrAddr_9_0[10];
	pseudo_bit_t _unused_0[25];
};
struct QIB_7322_SendPbcArrayUnCorErrLog {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SendPbcArrayUnCorErrLog_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_SBufVL15ArrayUnCorErrLogA_offset 0x000008c0UL
struct QIB_7322_SBufVL15ArrayUnCorErrLogA_pb {
	pseudo_bit_t SBufVL15ArrayUnCorErrData_63_0[64];
};
struct QIB_7322_SBufVL15ArrayUnCorErrLogA {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SBufVL15ArrayUnCorErrLogA_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_PcieCplDataBufrCorErrLogA_offset 0x00000900UL
struct QIB_7322_PcieCplDataBufrCorErrLogA_pb {
	pseudo_bit_t PcieCplDataBufrCorErrData_63_0[64];
};
struct QIB_7322_PcieCplDataBufrCorErrLogA {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_PcieCplDataBufrCorErrLogA_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_PcieCplDataBufrCorErrLogB_offset 0x00000908UL
struct QIB_7322_PcieCplDataBufrCorErrLogB_pb {
	pseudo_bit_t PcieCplDataBufrCorErrData_127_64[64];
};
struct QIB_7322_PcieCplDataBufrCorErrLogB {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_PcieCplDataBufrCorErrLogB_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_PcieCplDataBufrCorErrLogC_offset 0x00000910UL
struct QIB_7322_PcieCplDataBufrCorErrLogC_pb {
	pseudo_bit_t PcieCplDataBufrCorErrData_136_128[9];
	pseudo_bit_t PcieCplDataBufrCorErrCheckBit_21_0[22];
	pseudo_bit_t PcieCplDataBufrCorErrAddr_13_0[14];
	pseudo_bit_t _unused_0[19];
};
struct QIB_7322_PcieCplDataBufrCorErrLogC {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_PcieCplDataBufrCorErrLogC_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_PcieCplHdrBufrCorErrLogA_offset 0x00000920UL
struct QIB_7322_PcieCplHdrBufrCorErrLogA_pb {
	pseudo_bit_t PcieCplHdrBufrCorErrHdr_63_0[64];
};
struct QIB_7322_PcieCplHdrBufrCorErrLogA {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_PcieCplHdrBufrCorErrLogA_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_PcieCplHdrBufrCorErrLogB_offset 0x00000928UL
struct QIB_7322_PcieCplHdrBufrCorErrLogB_pb {
	pseudo_bit_t PcieCplHdrBufrCorErrHdr_103_64[40];
	pseudo_bit_t _unused_0[24];
};
struct QIB_7322_PcieCplHdrBufrCorErrLogB {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_PcieCplHdrBufrCorErrLogB_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_PcieCplHdrBufrCorErrLogC_offset 0x00000930UL
struct QIB_7322_PcieCplHdrBufrCorErrLogC_pb {
	pseudo_bit_t PcieCplHdrBufrCorErrCheckBit_15_0[16];
	pseudo_bit_t PcieCplHdrBufrCorErrAddr_8_0[9];
	pseudo_bit_t _unused_0[39];
};
struct QIB_7322_PcieCplHdrBufrCorErrLogC {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_PcieCplHdrBufrCorErrLogC_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_PciePDataBufrCorErrLogA_offset 0x00000940UL
struct QIB_7322_PciePDataBufrCorErrLogA_pb {
	pseudo_bit_t PciePDataBufrCorErrData_63_0[64];
};
struct QIB_7322_PciePDataBufrCorErrLogA {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_PciePDataBufrCorErrLogA_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_PciePDataBufrCorErrLogB_offset 0x00000948UL
struct QIB_7322_PciePDataBufrCorErrLogB_pb {
	pseudo_bit_t PciePDataBufrCorErrData_127_64[64];
};
struct QIB_7322_PciePDataBufrCorErrLogB {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_PciePDataBufrCorErrLogB_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_PciePDataBufrCorErrLogC_offset 0x00000950UL
struct QIB_7322_PciePDataBufrCorErrLogC_pb {
	pseudo_bit_t PciePDataBufrCorErrData_136_128[9];
	pseudo_bit_t PciePDataBufrCorErrCheckBit_21_0[22];
	pseudo_bit_t PciePDataBufrCorErrAddr_13_0[14];
	pseudo_bit_t _unused_0[19];
};
struct QIB_7322_PciePDataBufrCorErrLogC {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_PciePDataBufrCorErrLogC_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_PciePHdrBufrCorErrLogA_offset 0x00000960UL
struct QIB_7322_PciePHdrBufrCorErrLogA_pb {
	pseudo_bit_t PciePHdrBufrCorErrData_63_0[64];
};
struct QIB_7322_PciePHdrBufrCorErrLogA {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_PciePHdrBufrCorErrLogA_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_PciePHdrBufrCorErrLogB_offset 0x00000968UL
struct QIB_7322_PciePHdrBufrCorErrLogB_pb {
	pseudo_bit_t PciePHdrBufrCorErrData_107_64[44];
	pseudo_bit_t _unused_0[20];
};
struct QIB_7322_PciePHdrBufrCorErrLogB {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_PciePHdrBufrCorErrLogB_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_PciePHdrBufrCorErrLogC_offset 0x00000970UL
struct QIB_7322_PciePHdrBufrCorErrLogC_pb {
	pseudo_bit_t PciePHdrBufrCorErrCheckBit_15_0[16];
	pseudo_bit_t PciePHdrBufrCorErrAddr_8_0[9];
	pseudo_bit_t _unused_0[39];
};
struct QIB_7322_PciePHdrBufrCorErrLogC {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_PciePHdrBufrCorErrLogC_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_PcieRetryBufrCorErrLogA_offset 0x00000980UL
struct QIB_7322_PcieRetryBufrCorErrLogA_pb {
	pseudo_bit_t PcieRetryBufrCorErrData_63_0[64];
};
struct QIB_7322_PcieRetryBufrCorErrLogA {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_PcieRetryBufrCorErrLogA_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_PcieRetryBufrCorErrLogB_offset 0x00000988UL
struct QIB_7322_PcieRetryBufrCorErrLogB_pb {
	pseudo_bit_t PcieRetryBufrCorErrData_127_64[64];
};
struct QIB_7322_PcieRetryBufrCorErrLogB {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_PcieRetryBufrCorErrLogB_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_PcieRetryBufrCorErrLogC_offset 0x00000990UL
struct QIB_7322_PcieRetryBufrCorErrLogC_pb {
	pseudo_bit_t PcieRetryBufrCorErrData_133_128[6];
	pseudo_bit_t PcieRetryBufrCorErrCheckBit_20_0[21];
	pseudo_bit_t PcieRetryBufrCorErrAddr_13_0[14];
	pseudo_bit_t _unused_0[23];
};
struct QIB_7322_PcieRetryBufrCorErrLogC {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_PcieRetryBufrCorErrLogC_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxTIDArrayCorErrLogA_offset 0x00000a00UL
struct QIB_7322_RxTIDArrayCorErrLogA_pb {
	pseudo_bit_t RxTIDArrayCorErrData_39_0[40];
	pseudo_bit_t RxTIDArrayCorErrCheckBit_11_0[12];
	pseudo_bit_t _unused_0[12];
};
struct QIB_7322_RxTIDArrayCorErrLogA {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxTIDArrayCorErrLogA_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxTIDArrayCorErrLogB_offset 0x00000a08UL
struct QIB_7322_RxTIDArrayCorErrLogB_pb {
	pseudo_bit_t RxTIDArrayCorErrAddr_16_0[17];
	pseudo_bit_t _unused_0[47];
};
struct QIB_7322_RxTIDArrayCorErrLogB {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxTIDArrayCorErrLogB_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxEagerArrayCorErrLogA_offset 0x00000a10UL
struct QIB_7322_RxEagerArrayCorErrLogA_pb {
	pseudo_bit_t RxEagerArrayCorErrData_39_0[40];
	pseudo_bit_t RxEagerArrayCorErrCheckBit_11_0[12];
	pseudo_bit_t _unused_0[12];
};
struct QIB_7322_RxEagerArrayCorErrLogA {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxEagerArrayCorErrLogA_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxEagerArrayCorErrLogB_offset 0x00000a18UL
struct QIB_7322_RxEagerArrayCorErrLogB_pb {
	pseudo_bit_t RxEagerArrayCorErrAddr_17_0[18];
	pseudo_bit_t _unused_0[46];
};
struct QIB_7322_RxEagerArrayCorErrLogB {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxEagerArrayCorErrLogB_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_SBufMainArrayCorErrLogA_offset 0x00000a80UL
struct QIB_7322_SBufMainArrayCorErrLogA_pb {
	pseudo_bit_t SBufMainArrayCorErrData_63_0[64];
};
struct QIB_7322_SBufMainArrayCorErrLogA {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SBufMainArrayCorErrLogA_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_SBufMainArrayCorErrLogB_offset 0x00000a88UL
struct QIB_7322_SBufMainArrayCorErrLogB_pb {
	pseudo_bit_t SBufMainArrayCorErrData_127_64[64];
};
struct QIB_7322_SBufMainArrayCorErrLogB {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SBufMainArrayCorErrLogB_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_SBufMainArrayCorErrLogC_offset 0x00000a90UL
struct QIB_7322_SBufMainArrayCorErrLogC_pb {
	pseudo_bit_t SBufMainArrayCorErrCheckBit_27_0[28];
	pseudo_bit_t SBufMainArrayCorErrAddr_18_0[19];
	pseudo_bit_t _unused_0[13];
	pseudo_bit_t SBufMainArrayCorErrDword_3_0[4];
};
struct QIB_7322_SBufMainArrayCorErrLogC {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SBufMainArrayCorErrLogC_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_SBufExtraArrayCorErrLogA_offset 0x00000a98UL
struct QIB_7322_SBufExtraArrayCorErrLogA_pb {
	pseudo_bit_t SBufExtraArrayCorErrData_63_0[64];
};
struct QIB_7322_SBufExtraArrayCorErrLogA {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SBufExtraArrayCorErrLogA_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_SBufExtraArrayCorErrLogB_offset 0x00000aa0UL
struct QIB_7322_SBufExtraArrayCorErrLogB_pb {
	pseudo_bit_t SBufExtraArrayCorErrData_127_64[64];
};
struct QIB_7322_SBufExtraArrayCorErrLogB {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SBufExtraArrayCorErrLogB_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_SBufExtraArrayCorErrLogC_offset 0x00000aa8UL
struct QIB_7322_SBufExtraArrayCorErrLogC_pb {
	pseudo_bit_t SBufExtraArrayCorErrCheckBit_27_0[28];
	pseudo_bit_t SBufExtraArrayCorErrAddr_14_0[15];
	pseudo_bit_t _unused_0[17];
	pseudo_bit_t SBufExtraArrayCorErrAdd_3_0[4];
};
struct QIB_7322_SBufExtraArrayCorErrLogC {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SBufExtraArrayCorErrLogC_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendPbcArrayCorErrLog_offset 0x00000ab0UL
struct QIB_7322_SendPbcArrayCorErrLog_pb {
	pseudo_bit_t SendPbcArrayCorErrData_21_0[22];
	pseudo_bit_t SendPbcArrayCorErrCheckBit_6_0[7];
	pseudo_bit_t SendPbcArrayCorErrAddr_9_0[10];
	pseudo_bit_t _unused_0[25];
};
struct QIB_7322_SendPbcArrayCorErrLog {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SendPbcArrayCorErrLog_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_SBufVL15ArrayCorErrLogA_offset 0x00000ac0UL
struct QIB_7322_SBufVL15ArrayCorErrLogA_pb {
	pseudo_bit_t SBufVL15ArrayCorErrData_63_0[64];
};
struct QIB_7322_SBufVL15ArrayCorErrLogA {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SBufVL15ArrayCorErrLogA_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvAvailTimeOut0_offset 0x00000c00UL
struct QIB_7322_RcvAvailTimeOut0_pb {
	pseudo_bit_t RcvAvailTOReload[16];
	pseudo_bit_t RcvAvailTOCount[16];
	pseudo_bit_t _unused_0[32];
};
struct QIB_7322_RcvAvailTimeOut0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvAvailTimeOut0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_CntrRegBase_0_offset 0x00001028UL
/* Default value: 0x0000000000012000 */

#define QIB_7322_ErrMask_0_offset 0x00001080UL
struct QIB_7322_ErrMask_0_pb {
	pseudo_bit_t RcvFormatErrMask[1];
	pseudo_bit_t RcvVCRCErrMask[1];
	pseudo_bit_t RcvICRCErrMask[1];
	pseudo_bit_t RcvMinPktLenErrMask[1];
	pseudo_bit_t RcvMaxPktLenErrMask[1];
	pseudo_bit_t RcvLongPktLenErrMask[1];
	pseudo_bit_t RcvShortPktLenErrMask[1];
	pseudo_bit_t RcvUnexpectedCharErrMask[1];
	pseudo_bit_t RcvUnsupportedVLErrMask[1];
	pseudo_bit_t RcvEBPErrMask[1];
	pseudo_bit_t RcvIBFlowErrMask[1];
	pseudo_bit_t RcvBadVersionErrMask[1];
	pseudo_bit_t _unused_0[2];
	pseudo_bit_t RcvBadTidErrMask[1];
	pseudo_bit_t RcvHdrLenErrMask[1];
	pseudo_bit_t RcvHdrErrMask[1];
	pseudo_bit_t RcvIBLostLinkErrMask[1];
	pseudo_bit_t _unused_1[11];
	pseudo_bit_t SendMinPktLenErrMask[1];
	pseudo_bit_t SendMaxPktLenErrMask[1];
	pseudo_bit_t SendUnderRunErrMask[1];
	pseudo_bit_t SendPktLenErrMask[1];
	pseudo_bit_t SendDroppedSmpPktErrMask[1];
	pseudo_bit_t SendDroppedDataPktErrMask[1];
	pseudo_bit_t _unused_2[1];
	pseudo_bit_t SendUnexpectedPktNumErrMask[1];
	pseudo_bit_t SendUnsupportedVLErrMask[1];
	pseudo_bit_t SendBufMisuseErrMask[1];
	pseudo_bit_t SDmaGenMismatchErrMask[1];
	pseudo_bit_t SDmaOutOfBoundErrMask[1];
	pseudo_bit_t SDmaTailOutOfBoundErrMask[1];
	pseudo_bit_t SDmaBaseErrMask[1];
	pseudo_bit_t SDma1stDescErrMask[1];
	pseudo_bit_t SDmaRpyTagErrMask[1];
	pseudo_bit_t SDmaDwEnErrMask[1];
	pseudo_bit_t SDmaMissingDwErrMask[1];
	pseudo_bit_t SDmaUnexpDataErrMask[1];
	pseudo_bit_t SDmaDescAddrMisalignErrMask[1];
	pseudo_bit_t SDmaHaltErrMask[1];
	pseudo_bit_t _unused_3[4];
	pseudo_bit_t VL15BufMisuseErrMask[1];
	pseudo_bit_t _unused_4[2];
	pseudo_bit_t SHeadersErrMask[1];
	pseudo_bit_t IBStatusChangedMask[1];
	pseudo_bit_t _unused_5[5];
};
struct QIB_7322_ErrMask_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_ErrMask_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_ErrStatus_0_offset 0x00001088UL
struct QIB_7322_ErrStatus_0_pb {
	pseudo_bit_t RcvFormatErr[1];
	pseudo_bit_t RcvVCRCErr[1];
	pseudo_bit_t RcvICRCErr[1];
	pseudo_bit_t RcvMinPktLenErr[1];
	pseudo_bit_t RcvMaxPktLenErr[1];
	pseudo_bit_t RcvLongPktLenErr[1];
	pseudo_bit_t RcvShortPktLenErr[1];
	pseudo_bit_t RcvUnexpectedCharErr[1];
	pseudo_bit_t RcvUnsupportedVLErr[1];
	pseudo_bit_t RcvEBPErr[1];
	pseudo_bit_t RcvIBFlowErr[1];
	pseudo_bit_t RcvBadVersionErr[1];
	pseudo_bit_t _unused_0[2];
	pseudo_bit_t RcvBadTidErr[1];
	pseudo_bit_t RcvHdrLenErr[1];
	pseudo_bit_t RcvHdrErr[1];
	pseudo_bit_t RcvIBLostLinkErr[1];
	pseudo_bit_t _unused_1[11];
	pseudo_bit_t SendMinPktLenErr[1];
	pseudo_bit_t SendMaxPktLenErr[1];
	pseudo_bit_t SendUnderRunErr[1];
	pseudo_bit_t SendPktLenErr[1];
	pseudo_bit_t SendDroppedSmpPktErr[1];
	pseudo_bit_t SendDroppedDataPktErr[1];
	pseudo_bit_t _unused_2[1];
	pseudo_bit_t SendUnexpectedPktNumErr[1];
	pseudo_bit_t SendUnsupportedVLErr[1];
	pseudo_bit_t SendBufMisuseErr[1];
	pseudo_bit_t SDmaGenMismatchErr[1];
	pseudo_bit_t SDmaOutOfBoundErr[1];
	pseudo_bit_t SDmaTailOutOfBoundErr[1];
	pseudo_bit_t SDmaBaseErr[1];
	pseudo_bit_t SDma1stDescErr[1];
	pseudo_bit_t SDmaRpyTagErr[1];
	pseudo_bit_t SDmaDwEnErr[1];
	pseudo_bit_t SDmaMissingDwErr[1];
	pseudo_bit_t SDmaUnexpDataErr[1];
	pseudo_bit_t SDmaDescAddrMisalignErr[1];
	pseudo_bit_t SDmaHaltErr[1];
	pseudo_bit_t _unused_3[4];
	pseudo_bit_t VL15BufMisuseErr[1];
	pseudo_bit_t _unused_4[2];
	pseudo_bit_t SHeadersErr[1];
	pseudo_bit_t IBStatusChanged[1];
	pseudo_bit_t _unused_5[5];
};
struct QIB_7322_ErrStatus_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_ErrStatus_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_ErrClear_0_offset 0x00001090UL
struct QIB_7322_ErrClear_0_pb {
	pseudo_bit_t RcvFormatErrClear[1];
	pseudo_bit_t RcvVCRCErrClear[1];
	pseudo_bit_t RcvICRCErrClear[1];
	pseudo_bit_t RcvMinPktLenErrClear[1];
	pseudo_bit_t RcvMaxPktLenErrClear[1];
	pseudo_bit_t RcvLongPktLenErrClear[1];
	pseudo_bit_t RcvShortPktLenErrClear[1];
	pseudo_bit_t RcvUnexpectedCharErrClear[1];
	pseudo_bit_t RcvUnsupportedVLErrClear[1];
	pseudo_bit_t RcvEBPErrClear[1];
	pseudo_bit_t RcvIBFlowErrClear[1];
	pseudo_bit_t RcvBadVersionErrClear[1];
	pseudo_bit_t _unused_0[2];
	pseudo_bit_t RcvBadTidErrClear[1];
	pseudo_bit_t RcvHdrLenErrClear[1];
	pseudo_bit_t RcvHdrErrClear[1];
	pseudo_bit_t RcvIBLostLinkErrClear[1];
	pseudo_bit_t _unused_1[11];
	pseudo_bit_t SendMinPktLenErrClear[1];
	pseudo_bit_t SendMaxPktLenErrClear[1];
	pseudo_bit_t SendUnderRunErrClear[1];
	pseudo_bit_t SendPktLenErrClear[1];
	pseudo_bit_t SendDroppedSmpPktErrClear[1];
	pseudo_bit_t SendDroppedDataPktErrClear[1];
	pseudo_bit_t _unused_2[1];
	pseudo_bit_t SendUnexpectedPktNumErrClear[1];
	pseudo_bit_t SendUnsupportedVLErrClear[1];
	pseudo_bit_t SendBufMisuseErrClear[1];
	pseudo_bit_t SDmaGenMismatchErrClear[1];
	pseudo_bit_t SDmaOutOfBoundErrClear[1];
	pseudo_bit_t SDmaTailOutOfBoundErrClear[1];
	pseudo_bit_t SDmaBaseErrClear[1];
	pseudo_bit_t SDma1stDescErrClear[1];
	pseudo_bit_t SDmaRpyTagErrClear[1];
	pseudo_bit_t SDmaDwEnErrClear[1];
	pseudo_bit_t SDmaMissingDwErrClear[1];
	pseudo_bit_t SDmaUnexpDataErrClear[1];
	pseudo_bit_t SDmaDescAddrMisalignErrClear[1];
	pseudo_bit_t SDmaHaltErrClear[1];
	pseudo_bit_t _unused_3[4];
	pseudo_bit_t VL15BufMisuseErrClear[1];
	pseudo_bit_t _unused_4[2];
	pseudo_bit_t SHeadersErrClear[1];
	pseudo_bit_t IBStatusChangedClear[1];
	pseudo_bit_t _unused_5[5];
};
struct QIB_7322_ErrClear_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_ErrClear_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_TXEStatus_0_offset 0x000010b8UL
struct QIB_7322_TXEStatus_0_pb {
	pseudo_bit_t LaFifoEmpty_VL0[1];
	pseudo_bit_t LaFifoEmpty_VL1[1];
	pseudo_bit_t LaFifoEmpty_VL2[1];
	pseudo_bit_t LaFifoEmpty_VL3[1];
	pseudo_bit_t LaFifoEmpty_VL4[1];
	pseudo_bit_t LaFifoEmpty_VL5[1];
	pseudo_bit_t LaFifoEmpty_VL6[1];
	pseudo_bit_t LaFifoEmpty_VL7[1];
	pseudo_bit_t _unused_0[7];
	pseudo_bit_t LaFifoEmpty_VL15[1];
	pseudo_bit_t _unused_1[14];
	pseudo_bit_t RmFifoEmpty[1];
	pseudo_bit_t TXE_IBC_Idle[1];
	pseudo_bit_t _unused_2[32];
};
struct QIB_7322_TXEStatus_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_TXEStatus_0_pb );
};
/* Default value: 0x0000000XC00080FF */

#define QIB_7322_RcvCtrl_0_offset 0x00001100UL
struct QIB_7322_RcvCtrl_0_pb {
	pseudo_bit_t ContextEnableKernel[1];
	pseudo_bit_t _unused_0[1];
	pseudo_bit_t ContextEnableUser[16];
	pseudo_bit_t _unused_1[21];
	pseudo_bit_t RcvIBPortEnable[1];
	pseudo_bit_t RcvQPMapEnable[1];
	pseudo_bit_t RcvPartitionKeyDisable[1];
	pseudo_bit_t RcvResetCredit[1];
	pseudo_bit_t _unused_2[21];
};
struct QIB_7322_RcvCtrl_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvCtrl_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvBTHQP_0_offset 0x00001108UL
struct QIB_7322_RcvBTHQP_0_pb {
	pseudo_bit_t RcvBTHQP[24];
	pseudo_bit_t _unused_0[40];
};
struct QIB_7322_RcvBTHQP_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvBTHQP_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvQPMapTableA_0_offset 0x00001110UL
struct QIB_7322_RcvQPMapTableA_0_pb {
	pseudo_bit_t RcvQPMapContext0[5];
	pseudo_bit_t RcvQPMapContext1[5];
	pseudo_bit_t RcvQPMapContext2[5];
	pseudo_bit_t RcvQPMapContext3[5];
	pseudo_bit_t RcvQPMapContext4[5];
	pseudo_bit_t RcvQPMapContext5[5];
	pseudo_bit_t _unused_0[34];
};
struct QIB_7322_RcvQPMapTableA_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvQPMapTableA_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvQPMapTableB_0_offset 0x00001118UL
struct QIB_7322_RcvQPMapTableB_0_pb {
	pseudo_bit_t RcvQPMapContext6[5];
	pseudo_bit_t RcvQPMapContext7[5];
	pseudo_bit_t RcvQPMapContext8[5];
	pseudo_bit_t RcvQPMapContext9[5];
	pseudo_bit_t RcvQPMapContext10[5];
	pseudo_bit_t RcvQPMapContext11[5];
	pseudo_bit_t _unused_0[34];
};
struct QIB_7322_RcvQPMapTableB_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvQPMapTableB_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvQPMapTableC_0_offset 0x00001120UL
struct QIB_7322_RcvQPMapTableC_0_pb {
	pseudo_bit_t RcvQPMapContext12[5];
	pseudo_bit_t RcvQPMapContext13[5];
	pseudo_bit_t RcvQPMapContext14[5];
	pseudo_bit_t RcvQPMapContext15[5];
	pseudo_bit_t RcvQPMapContext16[5];
	pseudo_bit_t RcvQPMapContext17[5];
	pseudo_bit_t _unused_0[34];
};
struct QIB_7322_RcvQPMapTableC_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvQPMapTableC_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvQPMapTableD_0_offset 0x00001128UL
struct QIB_7322_RcvQPMapTableD_0_pb {
	pseudo_bit_t RcvQPMapContext18[5];
	pseudo_bit_t RcvQPMapContext19[5];
	pseudo_bit_t RcvQPMapContext20[5];
	pseudo_bit_t RcvQPMapContext21[5];
	pseudo_bit_t RcvQPMapContext22[5];
	pseudo_bit_t RcvQPMapContext23[5];
	pseudo_bit_t _unused_0[34];
};
struct QIB_7322_RcvQPMapTableD_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvQPMapTableD_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvQPMapTableE_0_offset 0x00001130UL
struct QIB_7322_RcvQPMapTableE_0_pb {
	pseudo_bit_t RcvQPMapContext24[5];
	pseudo_bit_t RcvQPMapContext25[5];
	pseudo_bit_t RcvQPMapContext26[5];
	pseudo_bit_t RcvQPMapContext27[5];
	pseudo_bit_t RcvQPMapContext28[5];
	pseudo_bit_t RcvQPMapContext29[5];
	pseudo_bit_t _unused_0[34];
};
struct QIB_7322_RcvQPMapTableE_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvQPMapTableE_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvQPMapTableF_0_offset 0x00001138UL
struct QIB_7322_RcvQPMapTableF_0_pb {
	pseudo_bit_t RcvQPMapContext30[5];
	pseudo_bit_t RcvQPMapContext31[5];
	pseudo_bit_t _unused_0[54];
};
struct QIB_7322_RcvQPMapTableF_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvQPMapTableF_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_PSStat_0_offset 0x00001140UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_PSStart_0_offset 0x00001148UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_PSInterval_0_offset 0x00001150UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvStatus_0_offset 0x00001160UL
struct QIB_7322_RcvStatus_0_pb {
	pseudo_bit_t RxPktInProgress[1];
	pseudo_bit_t DmaeqBlockingContext[5];
	pseudo_bit_t _unused_0[58];
};
struct QIB_7322_RcvStatus_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvStatus_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvPartitionKey_0_offset 0x00001168UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvQPMulticastContext_0_offset 0x00001170UL
struct QIB_7322_RcvQPMulticastContext_0_pb {
	pseudo_bit_t RcvQpMcContext[5];
	pseudo_bit_t _unused_0[59];
};
struct QIB_7322_RcvQPMulticastContext_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvQPMulticastContext_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvPktLEDCnt_0_offset 0x00001178UL
struct QIB_7322_RcvPktLEDCnt_0_pb {
	pseudo_bit_t OFFperiod[32];
	pseudo_bit_t ONperiod[32];
};
struct QIB_7322_RcvPktLEDCnt_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvPktLEDCnt_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendDmaIdleCnt_0_offset 0x00001180UL
struct QIB_7322_SendDmaIdleCnt_0_pb {
	pseudo_bit_t SendDmaIdleCnt[16];
	pseudo_bit_t _unused_0[48];
};
struct QIB_7322_SendDmaIdleCnt_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SendDmaIdleCnt_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendDmaReloadCnt_0_offset 0x00001188UL
struct QIB_7322_SendDmaReloadCnt_0_pb {
	pseudo_bit_t SendDmaReloadCnt[16];
	pseudo_bit_t _unused_0[48];
};
struct QIB_7322_SendDmaReloadCnt_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SendDmaReloadCnt_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendDmaDescCnt_0_offset 0x00001190UL
struct QIB_7322_SendDmaDescCnt_0_pb {
	pseudo_bit_t SendDmaDescCnt[16];
	pseudo_bit_t _unused_0[48];
};
struct QIB_7322_SendDmaDescCnt_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SendDmaDescCnt_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendCtrl_0_offset 0x000011c0UL
struct QIB_7322_SendCtrl_0_pb {
	pseudo_bit_t TxeAbortIbc[1];
	pseudo_bit_t TxeBypassIbc[1];
	pseudo_bit_t _unused_0[1];
	pseudo_bit_t SendEnable[1];
	pseudo_bit_t _unused_1[3];
	pseudo_bit_t ForceCreditUpToDate[1];
	pseudo_bit_t SDmaCleanup[1];
	pseudo_bit_t SDmaIntEnable[1];
	pseudo_bit_t SDmaSingleDescriptor[1];
	pseudo_bit_t SDmaEnable[1];
	pseudo_bit_t SDmaHalt[1];
	pseudo_bit_t TxeDrainLaFifo[1];
	pseudo_bit_t TxeDrainRmFifo[1];
	pseudo_bit_t IBVLArbiterEn[1];
	pseudo_bit_t _unused_2[48];
};
struct QIB_7322_SendCtrl_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SendCtrl_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendDmaBase_0_offset 0x000011f8UL
struct QIB_7322_SendDmaBase_0_pb {
	pseudo_bit_t SendDmaBase[48];
	pseudo_bit_t _unused_0[16];
};
struct QIB_7322_SendDmaBase_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SendDmaBase_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendDmaLenGen_0_offset 0x00001200UL
struct QIB_7322_SendDmaLenGen_0_pb {
	pseudo_bit_t Length[16];
	pseudo_bit_t Generation[3];
	pseudo_bit_t _unused_0[45];
};
struct QIB_7322_SendDmaLenGen_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SendDmaLenGen_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendDmaTail_0_offset 0x00001208UL
struct QIB_7322_SendDmaTail_0_pb {
	pseudo_bit_t SendDmaTail[16];
	pseudo_bit_t _unused_0[48];
};
struct QIB_7322_SendDmaTail_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SendDmaTail_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendDmaHead_0_offset 0x00001210UL
struct QIB_7322_SendDmaHead_0_pb {
	pseudo_bit_t SendDmaHead[16];
	pseudo_bit_t _unused_0[16];
	pseudo_bit_t InternalSendDmaHead[16];
	pseudo_bit_t _unused_1[16];
};
struct QIB_7322_SendDmaHead_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SendDmaHead_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendDmaHeadAddr_0_offset 0x00001218UL
struct QIB_7322_SendDmaHeadAddr_0_pb {
	pseudo_bit_t SendDmaHeadAddr[48];
	pseudo_bit_t _unused_0[16];
};
struct QIB_7322_SendDmaHeadAddr_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SendDmaHeadAddr_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendDmaBufMask0_0_offset 0x00001220UL
struct QIB_7322_SendDmaBufMask0_0_pb {
	pseudo_bit_t BufMask_63_0[64];
};
struct QIB_7322_SendDmaBufMask0_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SendDmaBufMask0_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendDmaStatus_0_offset 0x00001238UL
struct QIB_7322_SendDmaStatus_0_pb {
	pseudo_bit_t SplFifoDescIndex[16];
	pseudo_bit_t SplFifoBufNum[8];
	pseudo_bit_t SplFifoFull[1];
	pseudo_bit_t SplFifoEmpty[1];
	pseudo_bit_t SplFifoDisarmed[1];
	pseudo_bit_t SplFifoReadyToGo[1];
	pseudo_bit_t ScbFetchDescFlag[1];
	pseudo_bit_t ScbEntryValid[1];
	pseudo_bit_t ScbEmpty[1];
	pseudo_bit_t ScbFull[1];
	pseudo_bit_t RpyTag_7_0[8];
	pseudo_bit_t RpyLowAddr_6_0[7];
	pseudo_bit_t ScbDescIndex_13_0[14];
	pseudo_bit_t InternalSDmaHalt[1];
	pseudo_bit_t HaltInProg[1];
	pseudo_bit_t ScoreBoardDrainInProg[1];
};
struct QIB_7322_SendDmaStatus_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SendDmaStatus_0_pb );
};
/* Default value: 0x0000000042000000 */

#define QIB_7322_SendDmaPriorityThld_0_offset 0x00001258UL
struct QIB_7322_SendDmaPriorityThld_0_pb {
	pseudo_bit_t PriorityThreshold[4];
	pseudo_bit_t _unused_0[60];
};
struct QIB_7322_SendDmaPriorityThld_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SendDmaPriorityThld_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendHdrErrSymptom_0_offset 0x00001260UL
struct QIB_7322_SendHdrErrSymptom_0_pb {
	pseudo_bit_t PacketTooSmall[1];
	pseudo_bit_t RawIPV6[1];
	pseudo_bit_t SLIDFail[1];
	pseudo_bit_t QPFail[1];
	pseudo_bit_t PkeyFail[1];
	pseudo_bit_t GRHFail[1];
	pseudo_bit_t NonKeyPacket[1];
	pseudo_bit_t _unused_0[57];
};
struct QIB_7322_SendHdrErrSymptom_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SendHdrErrSymptom_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxCreditVL0_0_offset 0x00001280UL
struct QIB_7322_RxCreditVL0_0_pb {
	pseudo_bit_t RxMaxCreditVL[12];
	pseudo_bit_t _unused_0[4];
	pseudo_bit_t RxBufrConsumedVL[12];
	pseudo_bit_t _unused_1[36];
};
struct QIB_7322_RxCreditVL0_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxCreditVL0_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendDmaBufUsed0_0_offset 0x00001480UL
struct QIB_7322_SendDmaBufUsed0_0_pb {
	pseudo_bit_t BufUsed_63_0[64];
};
struct QIB_7322_SendDmaBufUsed0_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SendDmaBufUsed0_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendDmaReqTagUsed_0_offset 0x00001498UL
struct QIB_7322_SendDmaReqTagUsed_0_pb {
	pseudo_bit_t ReqTagUsed_7_0[8];
	pseudo_bit_t _unused_0[56];
};
struct QIB_7322_SendDmaReqTagUsed_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SendDmaReqTagUsed_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendCheckControl_0_offset 0x000014a8UL
struct QIB_7322_SendCheckControl_0_pb {
	pseudo_bit_t PacketTooSmall_En[1];
	pseudo_bit_t RawIPV6_En[1];
	pseudo_bit_t SLID_En[1];
	pseudo_bit_t BTHQP_En[1];
	pseudo_bit_t PKey_En[1];
	pseudo_bit_t _unused_0[59];
};
struct QIB_7322_SendCheckControl_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SendCheckControl_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendIBSLIDMask_0_offset 0x000014b0UL
struct QIB_7322_SendIBSLIDMask_0_pb {
	pseudo_bit_t SendIBSLIDMask_15_0[16];
	pseudo_bit_t _unused_0[48];
};
struct QIB_7322_SendIBSLIDMask_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SendIBSLIDMask_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendIBSLIDAssign_0_offset 0x000014b8UL
struct QIB_7322_SendIBSLIDAssign_0_pb {
	pseudo_bit_t SendIBSLIDAssign_15_0[16];
	pseudo_bit_t _unused_0[48];
};
struct QIB_7322_SendIBSLIDAssign_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SendIBSLIDAssign_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_IBCStatusA_0_offset 0x00001540UL
struct QIB_7322_IBCStatusA_0_pb {
	pseudo_bit_t LinkTrainingState[5];
	pseudo_bit_t LinkState[3];
	pseudo_bit_t LinkSpeedActive[1];
	pseudo_bit_t LinkWidthActive[1];
	pseudo_bit_t DDS_RXEQ_FAIL[1];
	pseudo_bit_t _unused_0[1];
	pseudo_bit_t IBRxLaneReversed[1];
	pseudo_bit_t IBTxLaneReversed[1];
	pseudo_bit_t ScrambleEn[1];
	pseudo_bit_t ScrambleCapRemote[1];
	pseudo_bit_t _unused_1[13];
	pseudo_bit_t LinkSpeedQDR[1];
	pseudo_bit_t TxReady[1];
	pseudo_bit_t _unused_2[1];
	pseudo_bit_t TxCreditOk_VL0[1];
	pseudo_bit_t TxCreditOk_VL1[1];
	pseudo_bit_t TxCreditOk_VL2[1];
	pseudo_bit_t TxCreditOk_VL3[1];
	pseudo_bit_t TxCreditOk_VL4[1];
	pseudo_bit_t TxCreditOk_VL5[1];
	pseudo_bit_t TxCreditOk_VL6[1];
	pseudo_bit_t TxCreditOk_VL7[1];
	pseudo_bit_t _unused_3[24];
};
struct QIB_7322_IBCStatusA_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_IBCStatusA_0_pb );
};
/* Default value: 0x0000000000000X02 */

#define QIB_7322_IBCStatusB_0_offset 0x00001548UL
struct QIB_7322_IBCStatusB_0_pb {
	pseudo_bit_t LinkRoundTripLatency[26];
	pseudo_bit_t ReqDDSLocalFromRmt[4];
	pseudo_bit_t RxEqLocalDevice[2];
	pseudo_bit_t heartbeat_crosstalk[4];
	pseudo_bit_t heartbeat_timed_out[1];
	pseudo_bit_t ibsd_adaptation_timer_started[1];
	pseudo_bit_t ibsd_adaptation_timer_reached_threshold[1];
	pseudo_bit_t ibsd_adaptation_timer_debug[1];
	pseudo_bit_t _unused_0[24];
};
struct QIB_7322_IBCStatusB_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_IBCStatusB_0_pb );
};
/* Default value: 0x00000000XXXXXXXX */

#define QIB_7322_IBCCtrlA_0_offset 0x00001560UL
struct QIB_7322_IBCCtrlA_0_pb {
	pseudo_bit_t FlowCtrlPeriod[8];
	pseudo_bit_t FlowCtrlWaterMark[8];
	pseudo_bit_t LinkInitCmd[3];
	pseudo_bit_t LinkCmd[2];
	pseudo_bit_t MaxPktLen[11];
	pseudo_bit_t PhyerrThreshold[4];
	pseudo_bit_t OverrunThreshold[4];
	pseudo_bit_t _unused_0[8];
	pseudo_bit_t NumVLane[3];
	pseudo_bit_t _unused_1[9];
	pseudo_bit_t IBStatIntReductionEn[1];
	pseudo_bit_t IBLinkEn[1];
	pseudo_bit_t LinkDownDefaultState[1];
	pseudo_bit_t Loopback[1];
};
struct QIB_7322_IBCCtrlA_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_IBCCtrlA_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_IBCCtrlB_0_offset 0x00001568UL
struct QIB_7322_IBCCtrlB_0_pb {
	pseudo_bit_t IB_ENHANCED_MODE[1];
	pseudo_bit_t SD_SPEED[1];
	pseudo_bit_t SD_SPEED_SDR[1];
	pseudo_bit_t SD_SPEED_DDR[1];
	pseudo_bit_t SD_SPEED_QDR[1];
	pseudo_bit_t IB_NUM_CHANNELS[2];
	pseudo_bit_t IB_POLARITY_REV_SUPP[1];
	pseudo_bit_t IB_LANE_REV_SUPPORTED[1];
	pseudo_bit_t SD_RX_EQUAL_ENABLE[1];
	pseudo_bit_t SD_ADD_ENB[1];
	pseudo_bit_t SD_DDSV[1];
	pseudo_bit_t SD_DDS[4];
	pseudo_bit_t HRTBT_ENB[1];
	pseudo_bit_t HRTBT_AUTO[1];
	pseudo_bit_t HRTBT_PORT[8];
	pseudo_bit_t HRTBT_REQ[1];
	pseudo_bit_t IB_ENABLE_FILT_DPKT[1];
	pseudo_bit_t _unused_0[4];
	pseudo_bit_t IB_DLID[16];
	pseudo_bit_t IB_DLID_MASK[16];
};
struct QIB_7322_IBCCtrlB_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_IBCCtrlB_0_pb );
};
/* Default value: 0x00000000000305FF */

#define QIB_7322_IBCCtrlC_0_offset 0x00001570UL
struct QIB_7322_IBCCtrlC_0_pb {
	pseudo_bit_t IB_FRONT_PORCH[5];
	pseudo_bit_t IB_BACK_PORCH[5];
	pseudo_bit_t _unused_0[54];
};
struct QIB_7322_IBCCtrlC_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_IBCCtrlC_0_pb );
};
/* Default value: 0x0000000000000301 */

#define QIB_7322_HRTBT_GUID_0_offset 0x00001588UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_IB_SDTEST_IF_TX_0_offset 0x00001590UL
struct QIB_7322_IB_SDTEST_IF_TX_0_pb {
	pseudo_bit_t TS_T_TX_VALID[1];
	pseudo_bit_t TS_3_TX_VALID[1];
	pseudo_bit_t VL_CAP[2];
	pseudo_bit_t CREDIT_CHANGE[1];
	pseudo_bit_t _unused_0[6];
	pseudo_bit_t TS_TX_OPCODE[2];
	pseudo_bit_t TS_TX_SPEED[3];
	pseudo_bit_t _unused_1[16];
	pseudo_bit_t TS_TX_TX_CFG[16];
	pseudo_bit_t TS_TX_RX_CFG[16];
};
struct QIB_7322_IB_SDTEST_IF_TX_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_IB_SDTEST_IF_TX_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_IB_SDTEST_IF_RX_0_offset 0x00001598UL
struct QIB_7322_IB_SDTEST_IF_RX_0_pb {
	pseudo_bit_t TS_T_RX_VALID[1];
	pseudo_bit_t TS_3_RX_VALID[1];
	pseudo_bit_t _unused_0[14];
	pseudo_bit_t TS_RX_A[8];
	pseudo_bit_t TS_RX_B[8];
	pseudo_bit_t TS_RX_TX_CFG[16];
	pseudo_bit_t TS_RX_RX_CFG[16];
};
struct QIB_7322_IB_SDTEST_IF_RX_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_IB_SDTEST_IF_RX_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_IBNCModeCtrl_0_offset 0x000015b8UL
struct QIB_7322_IBNCModeCtrl_0_pb {
	pseudo_bit_t TSMEnable_send_TS1[1];
	pseudo_bit_t TSMEnable_send_TS2[1];
	pseudo_bit_t TSMEnable_ignore_TSM_on_rx[1];
	pseudo_bit_t _unused_0[5];
	pseudo_bit_t TSMCode_TS1[9];
	pseudo_bit_t TSMCode_TS2[9];
	pseudo_bit_t _unused_1[6];
	pseudo_bit_t ScrambleCapLocal[1];
	pseudo_bit_t ScrambleCapRemoteMask[1];
	pseudo_bit_t ScrambleCapRemoteForce[1];
	pseudo_bit_t _unused_2[29];
};
struct QIB_7322_IBNCModeCtrl_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_IBNCModeCtrl_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_IBSerdesStatus_0_offset 0x000015d0UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_IBPCSConfig_0_offset 0x000015d8UL
struct QIB_7322_IBPCSConfig_0_pb {
	pseudo_bit_t tx_rx_reset[1];
	pseudo_bit_t xcv_treset[1];
	pseudo_bit_t xcv_rreset[1];
	pseudo_bit_t _unused_0[6];
	pseudo_bit_t link_sync_mask[10];
	pseudo_bit_t _unused_1[45];
};
struct QIB_7322_IBPCSConfig_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_IBPCSConfig_0_pb );
};
/* Default value: 0x0000000000000007 */

#define QIB_7322_IBSerdesCtrl_0_offset 0x000015e0UL
struct QIB_7322_IBSerdesCtrl_0_pb {
	pseudo_bit_t CMODE[7];
	pseudo_bit_t _unused_0[1];
	pseudo_bit_t TXIDLE[1];
	pseudo_bit_t RXPD[1];
	pseudo_bit_t TXPD[1];
	pseudo_bit_t PLLPD[1];
	pseudo_bit_t LPEN[1];
	pseudo_bit_t RXLOSEN[1];
	pseudo_bit_t _unused_1[1];
	pseudo_bit_t IB_LAT_MODE[1];
	pseudo_bit_t CGMODE[4];
	pseudo_bit_t CHANNEL_RESET_N[4];
	pseudo_bit_t DISABLE_RXLATOFF_SDR[1];
	pseudo_bit_t DISABLE_RXLATOFF_DDR[1];
	pseudo_bit_t DISABLE_RXLATOFF_QDR[1];
	pseudo_bit_t _unused_2[37];
};
struct QIB_7322_IBSerdesCtrl_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_IBSerdesCtrl_0_pb );
};
/* Default value: 0x0000000000FFA00F */

#define QIB_7322_IBSD_TX_DEEMPHASIS_OVERRIDE_0_offset 0x00001600UL
struct QIB_7322_IBSD_TX_DEEMPHASIS_OVERRIDE_0_pb {
	pseudo_bit_t txcn1_ena[3];
	pseudo_bit_t txcn1_xtra_emph0[2];
	pseudo_bit_t txcp1_ena[4];
	pseudo_bit_t txc0_ena[5];
	pseudo_bit_t txampcntl_d2a[4];
	pseudo_bit_t _unused_0[12];
	pseudo_bit_t reset_tx_deemphasis_override[1];
	pseudo_bit_t tx_override_deemphasis_select[1];
	pseudo_bit_t _unused_1[32];
};
struct QIB_7322_IBSD_TX_DEEMPHASIS_OVERRIDE_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_IBSD_TX_DEEMPHASIS_OVERRIDE_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_ADAPT_DISABLE_STATIC_SDR_0_offset 0x00001640UL
struct QIB_7322_ADAPT_DISABLE_STATIC_SDR_0_pb {
	pseudo_bit_t static_disable_rxenadfe_sdr_ch0[8];
	pseudo_bit_t static_disable_rxenadfe_sdr_ch1[8];
	pseudo_bit_t static_disable_rxenadfe_sdr_ch2[8];
	pseudo_bit_t static_disable_rxenadfe_sdr_ch3[8];
	pseudo_bit_t static_disable_rxenale_sdr_ch0[1];
	pseudo_bit_t static_disable_rxenale_sdr_ch1[1];
	pseudo_bit_t static_disable_rxenale_sdr_ch2[1];
	pseudo_bit_t static_disable_rxenale_sdr_ch3[1];
	pseudo_bit_t static_disable_rxenagain_sdr_ch0[1];
	pseudo_bit_t static_disable_rxenagain_sdr_ch1[1];
	pseudo_bit_t static_disable_rxenagain_sdr_ch2[1];
	pseudo_bit_t static_disable_rxenagain_sdr_ch3[1];
	pseudo_bit_t _unused_0[24];
};
struct QIB_7322_ADAPT_DISABLE_STATIC_SDR_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_ADAPT_DISABLE_STATIC_SDR_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_ADAPT_DISABLE_DYNAMIC_SDR_0_offset 0x00001648UL
struct QIB_7322_ADAPT_DISABLE_DYNAMIC_SDR_0_pb {
	pseudo_bit_t dyn_disable_rxenadfe_sdr_ch0[8];
	pseudo_bit_t dyn_disable_rxenadfe_sdr_ch1[8];
	pseudo_bit_t dyn_disable_rxenadfe_sdr_ch2[8];
	pseudo_bit_t dyn_disable_rxenadfe_sdr_ch3[8];
	pseudo_bit_t dyn_disable_rxenale_sdr_ch0[1];
	pseudo_bit_t dyn_disable_rxenale_sdr_ch1[1];
	pseudo_bit_t dyn_disable_rxenale_sdr_ch2[1];
	pseudo_bit_t dyn_disable_rxenale_sdr_ch3[1];
	pseudo_bit_t dyn_disable_rxenagain_sdr_ch0[1];
	pseudo_bit_t dyn_disable_rxenagain_sdr_ch1[1];
	pseudo_bit_t dyn_disable_rxenagain_sdr_ch2[1];
	pseudo_bit_t dyn_disable_rxenagain_sdr_ch3[1];
	pseudo_bit_t _unused_0[24];
};
struct QIB_7322_ADAPT_DISABLE_DYNAMIC_SDR_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_ADAPT_DISABLE_DYNAMIC_SDR_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_ADAPT_DISABLE_STATIC_DDR_0_offset 0x00001650UL
struct QIB_7322_ADAPT_DISABLE_STATIC_DDR_0_pb {
	pseudo_bit_t static_disable_rxenadfe_ddr_ch0[8];
	pseudo_bit_t static_disable_rxenadfe_ddr_ch1[8];
	pseudo_bit_t static_disable_rxenadfe_ddr_ch2[8];
	pseudo_bit_t static_disable_rxenadfe_ddr_ch3[8];
	pseudo_bit_t static_disable_rxenale_ddr_ch0[1];
	pseudo_bit_t static_disable_rxenale_ddr_ch1[1];
	pseudo_bit_t static_disable_rxenale_ddr_ch2[1];
	pseudo_bit_t static_disable_rxenale_ddr_ch3[1];
	pseudo_bit_t static_disable_rxenagain_ddr_ch0[1];
	pseudo_bit_t static_disable_rxenagain_ddr_ch1[1];
	pseudo_bit_t static_disable_rxenagain_ddr_ch2[1];
	pseudo_bit_t static_disable_rxenagain_ddr_ch3[1];
	pseudo_bit_t _unused_0[24];
};
struct QIB_7322_ADAPT_DISABLE_STATIC_DDR_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_ADAPT_DISABLE_STATIC_DDR_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_ADAPT_DISABLE_DYNAMIC_DDR_0_offset 0x00001658UL
struct QIB_7322_ADAPT_DISABLE_DYNAMIC_DDR_0_pb {
	pseudo_bit_t dyn_disable_rxenadfe_ddr_ch0[8];
	pseudo_bit_t dyn_disable_rxenadfe_ddr_ch1[8];
	pseudo_bit_t dyn_disable_rxenadfe_ddr_ch2[8];
	pseudo_bit_t dyn_disable_rxenadfe_ddr_ch3[8];
	pseudo_bit_t dyn_disable_rxenale_ddr_ch0[1];
	pseudo_bit_t dyn_disable_rxenale_ddr_ch1[1];
	pseudo_bit_t dyn_disable_rxenale_ddr_ch2[1];
	pseudo_bit_t dyn_disable_rxenale_ddr_ch3[1];
	pseudo_bit_t dyn_disable_rxenagain_ddr_ch0[1];
	pseudo_bit_t dyn_disable_rxenagain_ddr_ch1[1];
	pseudo_bit_t dyn_disable_rxenagain_ddr_ch2[1];
	pseudo_bit_t dyn_disable_rxenagain_ddr_ch3[1];
	pseudo_bit_t _unused_0[24];
};
struct QIB_7322_ADAPT_DISABLE_DYNAMIC_DDR_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_ADAPT_DISABLE_DYNAMIC_DDR_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_ADAPT_DISABLE_STATIC_QDR_0_offset 0x00001660UL
struct QIB_7322_ADAPT_DISABLE_STATIC_QDR_0_pb {
	pseudo_bit_t static_disable_rxenadfe_qdr_ch0[8];
	pseudo_bit_t static_disable_rxenadfe_qdr_ch1[8];
	pseudo_bit_t static_disable_rxenadfe_qdr_ch2[8];
	pseudo_bit_t static_disable_rxenadfe_qdr_ch3[8];
	pseudo_bit_t static_disable_rxenale_qdr_ch0[1];
	pseudo_bit_t static_disable_rxenale_qdr_ch1[1];
	pseudo_bit_t static_disable_rxenale_qdr_ch2[1];
	pseudo_bit_t static_disable_rxenale_qdr_ch3[1];
	pseudo_bit_t static_disable_rxenagain_qdr_ch0[1];
	pseudo_bit_t static_disable_rxenagain_qdr_ch1[1];
	pseudo_bit_t static_disable_rxenagain_qdr_ch2[1];
	pseudo_bit_t static_disable_rxenagain_qdr_ch3[1];
	pseudo_bit_t _unused_0[24];
};
struct QIB_7322_ADAPT_DISABLE_STATIC_QDR_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_ADAPT_DISABLE_STATIC_QDR_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_ADAPT_DISABLE_DYNAMIC_QDR_0_offset 0x00001668UL
struct QIB_7322_ADAPT_DISABLE_DYNAMIC_QDR_0_pb {
	pseudo_bit_t dyn_disable_rxenadfe_qdr_ch0[8];
	pseudo_bit_t dyn_disable_rxenadfe_qdr_ch1[8];
	pseudo_bit_t dyn_disable_rxenadfe_qdr_ch2[8];
	pseudo_bit_t dyn_disable_rxenadfe_qdr_ch3[8];
	pseudo_bit_t dyn_disable_rxenale_qdr_ch0[1];
	pseudo_bit_t dyn_disable_rxenale_qdr_ch1[1];
	pseudo_bit_t dyn_disable_rxenale_qdr_ch2[1];
	pseudo_bit_t dyn_disable_rxenale_qdr_ch3[1];
	pseudo_bit_t dyn_disable_rxenagain_qdr_ch0[1];
	pseudo_bit_t dyn_disable_rxenagain_qdr_ch1[1];
	pseudo_bit_t dyn_disable_rxenagain_qdr_ch2[1];
	pseudo_bit_t dyn_disable_rxenagain_qdr_ch3[1];
	pseudo_bit_t _unused_0[24];
};
struct QIB_7322_ADAPT_DISABLE_DYNAMIC_QDR_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_ADAPT_DISABLE_DYNAMIC_QDR_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_ADAPT_DISABLE_TIMER_THRESHOLD_0_offset 0x00001670UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxBufrUnCorErrLogA_0_offset 0x00001800UL
struct QIB_7322_RxBufrUnCorErrLogA_0_pb {
	pseudo_bit_t RxBufrUnCorErrData_63_0[64];
};
struct QIB_7322_RxBufrUnCorErrLogA_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxBufrUnCorErrLogA_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxBufrUnCorErrLogB_0_offset 0x00001808UL
struct QIB_7322_RxBufrUnCorErrLogB_0_pb {
	pseudo_bit_t RxBufrUnCorErrData_127_64[64];
};
struct QIB_7322_RxBufrUnCorErrLogB_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxBufrUnCorErrLogB_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxBufrUnCorErrLogC_0_offset 0x00001810UL
struct QIB_7322_RxBufrUnCorErrLogC_0_pb {
	pseudo_bit_t RxBufrUnCorErrData_191_128[64];
};
struct QIB_7322_RxBufrUnCorErrLogC_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxBufrUnCorErrLogC_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxBufrUnCorErrLogD_0_offset 0x00001818UL
struct QIB_7322_RxBufrUnCorErrLogD_0_pb {
	pseudo_bit_t RxBufrUnCorErrData_255_192[64];
};
struct QIB_7322_RxBufrUnCorErrLogD_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxBufrUnCorErrLogD_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxBufrUnCorErrLogE_0_offset 0x00001820UL
struct QIB_7322_RxBufrUnCorErrLogE_0_pb {
	pseudo_bit_t RxBufrUnCorErrData_258_256[3];
	pseudo_bit_t RxBufrUnCorErrCheckBit_36_0[37];
	pseudo_bit_t RxBufrUnCorErrAddr_15_0[16];
	pseudo_bit_t _unused_0[8];
};
struct QIB_7322_RxBufrUnCorErrLogE_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxBufrUnCorErrLogE_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxFlagUnCorErrLogA_0_offset 0x00001828UL
struct QIB_7322_RxFlagUnCorErrLogA_0_pb {
	pseudo_bit_t RxFlagUnCorErrData_63_0[64];
};
struct QIB_7322_RxFlagUnCorErrLogA_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxFlagUnCorErrLogA_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxFlagUnCorErrLogB_0_offset 0x00001830UL
struct QIB_7322_RxFlagUnCorErrLogB_0_pb {
	pseudo_bit_t RxFlagUnCorErrCheckBit_7_0[8];
	pseudo_bit_t RxFlagUnCorErrAddr_12_0[13];
	pseudo_bit_t _unused_0[43];
};
struct QIB_7322_RxFlagUnCorErrLogB_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxFlagUnCorErrLogB_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxLkupiqUnCorErrLogA_0_offset 0x00001840UL
struct QIB_7322_RxLkupiqUnCorErrLogA_0_pb {
	pseudo_bit_t RxLkupiqUnCorErrData_45_0[46];
	pseudo_bit_t RxLkupiqUnCorErrCheckBit_7_0[8];
	pseudo_bit_t _unused_0[10];
};
struct QIB_7322_RxLkupiqUnCorErrLogA_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxLkupiqUnCorErrLogA_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxLkupiqUnCorErrLogB_0_offset 0x00001848UL
struct QIB_7322_RxLkupiqUnCorErrLogB_0_pb {
	pseudo_bit_t RxLkupiqUnCorErrAddr_12_0[13];
	pseudo_bit_t _unused_0[51];
};
struct QIB_7322_RxLkupiqUnCorErrLogB_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxLkupiqUnCorErrLogB_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxHdrFifoUnCorErrLogA_0_offset 0x00001850UL
struct QIB_7322_RxHdrFifoUnCorErrLogA_0_pb {
	pseudo_bit_t RxHdrFifoUnCorErrData_63_0[64];
};
struct QIB_7322_RxHdrFifoUnCorErrLogA_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxHdrFifoUnCorErrLogA_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxHdrFifoUnCorErrLogB_0_offset 0x00001858UL
struct QIB_7322_RxHdrFifoUnCorErrLogB_0_pb {
	pseudo_bit_t RxHdrFifoUnCorErrData_127_64[64];
};
struct QIB_7322_RxHdrFifoUnCorErrLogB_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxHdrFifoUnCorErrLogB_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxHdrFifoUnCorErrLogC_0_offset 0x00001860UL
struct QIB_7322_RxHdrFifoUnCorErrLogC_0_pb {
	pseudo_bit_t RxHdrFifoUnCorErrCheckBit_15_0[16];
	pseudo_bit_t RxHdrFifoUnCorErrAddr_10_0[11];
	pseudo_bit_t _unused_0[37];
};
struct QIB_7322_RxHdrFifoUnCorErrLogC_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxHdrFifoUnCorErrLogC_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxDataFifoUnCorErrLogA_0_offset 0x00001868UL
struct QIB_7322_RxDataFifoUnCorErrLogA_0_pb {
	pseudo_bit_t RxDataFifoUnCorErrData_63_0[64];
};
struct QIB_7322_RxDataFifoUnCorErrLogA_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxDataFifoUnCorErrLogA_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxDataFifoUnCorErrLogB_0_offset 0x00001870UL
struct QIB_7322_RxDataFifoUnCorErrLogB_0_pb {
	pseudo_bit_t RxDataFifoUnCorErrData_127_64[64];
};
struct QIB_7322_RxDataFifoUnCorErrLogB_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxDataFifoUnCorErrLogB_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxDataFifoUnCorErrLogC_0_offset 0x00001878UL
struct QIB_7322_RxDataFifoUnCorErrLogC_0_pb {
	pseudo_bit_t RxDataFifoUnCorErrCheckBit_15_0[16];
	pseudo_bit_t RxDataFifoUnCorErrAddr_10_0[11];
	pseudo_bit_t _unused_0[37];
};
struct QIB_7322_RxDataFifoUnCorErrLogC_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxDataFifoUnCorErrLogC_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_LaFifoArray0UnCorErrLog_0_offset 0x00001880UL
struct QIB_7322_LaFifoArray0UnCorErrLog_0_pb {
	pseudo_bit_t LaFifoArray0UnCorErrData_34_0[35];
	pseudo_bit_t LaFifoArray0UnCorErrCheckBit_10_0[11];
	pseudo_bit_t LaFifoArray0UnCorErrAddr_10_0[11];
	pseudo_bit_t _unused_0[7];
};
struct QIB_7322_LaFifoArray0UnCorErrLog_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_LaFifoArray0UnCorErrLog_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RmFifoArrayUnCorErrLogA_0_offset 0x000018c0UL
struct QIB_7322_RmFifoArrayUnCorErrLogA_0_pb {
	pseudo_bit_t RmFifoArrayUnCorErrData_63_0[64];
};
struct QIB_7322_RmFifoArrayUnCorErrLogA_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RmFifoArrayUnCorErrLogA_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RmFifoArrayUnCorErrLogB_0_offset 0x000018c8UL
struct QIB_7322_RmFifoArrayUnCorErrLogB_0_pb {
	pseudo_bit_t RmFifoArrayUnCorErrData_127_64[64];
};
struct QIB_7322_RmFifoArrayUnCorErrLogB_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RmFifoArrayUnCorErrLogB_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RmFifoArrayUnCorErrLogC_0_offset 0x000018d0UL
struct QIB_7322_RmFifoArrayUnCorErrLogC_0_pb {
	pseudo_bit_t RmFifoArrayUnCorErrCheckBit_27_0[28];
	pseudo_bit_t RmFifoArrayUnCorErrAddr_13_0[14];
	pseudo_bit_t _unused_0[18];
	pseudo_bit_t RmFifoArrayUnCorErrDword_3_0[4];
};
struct QIB_7322_RmFifoArrayUnCorErrLogC_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RmFifoArrayUnCorErrLogC_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxBufrCorErrLogA_0_offset 0x00001900UL
struct QIB_7322_RxBufrCorErrLogA_0_pb {
	pseudo_bit_t RxBufrCorErrData_63_0[64];
};
struct QIB_7322_RxBufrCorErrLogA_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxBufrCorErrLogA_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxBufrCorErrLogB_0_offset 0x00001908UL
struct QIB_7322_RxBufrCorErrLogB_0_pb {
	pseudo_bit_t RxBufrCorErrData_127_64[64];
};
struct QIB_7322_RxBufrCorErrLogB_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxBufrCorErrLogB_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxBufrCorErrLogC_0_offset 0x00001910UL
struct QIB_7322_RxBufrCorErrLogC_0_pb {
	pseudo_bit_t RxBufrCorErrData_191_128[64];
};
struct QIB_7322_RxBufrCorErrLogC_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxBufrCorErrLogC_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxBufrCorErrLogD_0_offset 0x00001918UL
struct QIB_7322_RxBufrCorErrLogD_0_pb {
	pseudo_bit_t RxBufrCorErrData_255_192[64];
};
struct QIB_7322_RxBufrCorErrLogD_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxBufrCorErrLogD_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxBufrCorErrLogE_0_offset 0x00001920UL
struct QIB_7322_RxBufrCorErrLogE_0_pb {
	pseudo_bit_t RxBufrCorErrData_258_256[3];
	pseudo_bit_t RxBufrCorErrCheckBit_36_0[37];
	pseudo_bit_t RxBufrCorErrAddr_15_0[16];
	pseudo_bit_t _unused_0[8];
};
struct QIB_7322_RxBufrCorErrLogE_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxBufrCorErrLogE_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxFlagCorErrLogA_0_offset 0x00001928UL
struct QIB_7322_RxFlagCorErrLogA_0_pb {
	pseudo_bit_t RxFlagCorErrData_63_0[64];
};
struct QIB_7322_RxFlagCorErrLogA_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxFlagCorErrLogA_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxFlagCorErrLogB_0_offset 0x00001930UL
struct QIB_7322_RxFlagCorErrLogB_0_pb {
	pseudo_bit_t RxFlagCorErrCheckBit_7_0[8];
	pseudo_bit_t RxFlagCorErrAddr_12_0[13];
	pseudo_bit_t _unused_0[43];
};
struct QIB_7322_RxFlagCorErrLogB_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxFlagCorErrLogB_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxLkupiqCorErrLogA_0_offset 0x00001940UL
struct QIB_7322_RxLkupiqCorErrLogA_0_pb {
	pseudo_bit_t RxLkupiqCorErrData_45_0[46];
	pseudo_bit_t RxLkupiqCorErrCheckBit_7_0[8];
	pseudo_bit_t _unused_0[10];
};
struct QIB_7322_RxLkupiqCorErrLogA_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxLkupiqCorErrLogA_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxLkupiqCorErrLogB_0_offset 0x00001948UL
struct QIB_7322_RxLkupiqCorErrLogB_0_pb {
	pseudo_bit_t RxLkupiqCorErrAddr_12_0[13];
	pseudo_bit_t _unused_0[51];
};
struct QIB_7322_RxLkupiqCorErrLogB_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxLkupiqCorErrLogB_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxHdrFifoCorErrLogA_0_offset 0x00001950UL
struct QIB_7322_RxHdrFifoCorErrLogA_0_pb {
	pseudo_bit_t RxHdrFifoCorErrData_63_0[64];
};
struct QIB_7322_RxHdrFifoCorErrLogA_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxHdrFifoCorErrLogA_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxHdrFifoCorErrLogB_0_offset 0x00001958UL
struct QIB_7322_RxHdrFifoCorErrLogB_0_pb {
	pseudo_bit_t RxHdrFifoCorErrData_127_64[64];
};
struct QIB_7322_RxHdrFifoCorErrLogB_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxHdrFifoCorErrLogB_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxHdrFifoCorErrLogC_0_offset 0x00001960UL
struct QIB_7322_RxHdrFifoCorErrLogC_0_pb {
	pseudo_bit_t RxHdrFifoCorErrCheckBit_15_0[16];
	pseudo_bit_t RxHdrFifoCorErrAddr_10_0[11];
	pseudo_bit_t _unused_0[37];
};
struct QIB_7322_RxHdrFifoCorErrLogC_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxHdrFifoCorErrLogC_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxDataFifoCorErrLogA_0_offset 0x00001968UL
struct QIB_7322_RxDataFifoCorErrLogA_0_pb {
	pseudo_bit_t RxDataFifoCorErrData_63_0[64];
};
struct QIB_7322_RxDataFifoCorErrLogA_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxDataFifoCorErrLogA_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxDataFifoCorErrLogB_0_offset 0x00001970UL
struct QIB_7322_RxDataFifoCorErrLogB_0_pb {
	pseudo_bit_t RxDataFifoCorErrData_127_64[64];
};
struct QIB_7322_RxDataFifoCorErrLogB_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxDataFifoCorErrLogB_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxDataFifoCorErrLogC_0_offset 0x00001978UL
struct QIB_7322_RxDataFifoCorErrLogC_0_pb {
	pseudo_bit_t RxDataFifoCorErrCheckBit_15_0[16];
	pseudo_bit_t RxDataFifoCorErrAddr_10_0[11];
	pseudo_bit_t _unused_0[37];
};
struct QIB_7322_RxDataFifoCorErrLogC_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxDataFifoCorErrLogC_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_LaFifoArray0CorErrLog_0_offset 0x00001980UL
struct QIB_7322_LaFifoArray0CorErrLog_0_pb {
	pseudo_bit_t LaFifoArray0CorErrData_34_0[35];
	pseudo_bit_t LaFifoArray0CorErrCheckBit_10_0[11];
	pseudo_bit_t LaFifoArray0CorErrAddr_10_0[11];
	pseudo_bit_t _unused_0[7];
};
struct QIB_7322_LaFifoArray0CorErrLog_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_LaFifoArray0CorErrLog_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RmFifoArrayCorErrLogA_0_offset 0x000019c0UL
struct QIB_7322_RmFifoArrayCorErrLogA_0_pb {
	pseudo_bit_t RmFifoArrayCorErrData_63_0[64];
};
struct QIB_7322_RmFifoArrayCorErrLogA_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RmFifoArrayCorErrLogA_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RmFifoArrayCorErrLogB_0_offset 0x000019c8UL
struct QIB_7322_RmFifoArrayCorErrLogB_0_pb {
	pseudo_bit_t RmFifoArrayCorErrData_127_64[64];
};
struct QIB_7322_RmFifoArrayCorErrLogB_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RmFifoArrayCorErrLogB_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RmFifoArrayCorErrLogC_0_offset 0x000019d0UL
struct QIB_7322_RmFifoArrayCorErrLogC_0_pb {
	pseudo_bit_t RmFifoArrayCorErrCheckBit_27_0[28];
	pseudo_bit_t RmFifoArrayCorErrAddr_13_0[14];
	pseudo_bit_t _unused_0[18];
	pseudo_bit_t RmFifoArrayCorErrDword_3_0[4];
};
struct QIB_7322_RmFifoArrayCorErrLogC_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RmFifoArrayCorErrLogC_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_HighPriorityLimit_0_offset 0x00001bc0UL
struct QIB_7322_HighPriorityLimit_0_pb {
	pseudo_bit_t Limit[8];
	pseudo_bit_t _unused_0[56];
};
struct QIB_7322_HighPriorityLimit_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_HighPriorityLimit_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_LowPriority0_0_offset 0x00001c00UL
struct QIB_7322_LowPriority0_0_pb {
	pseudo_bit_t Weight[8];
	pseudo_bit_t _unused_0[8];
	pseudo_bit_t VirtualLane[3];
	pseudo_bit_t _unused_1[45];
};
struct QIB_7322_LowPriority0_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_LowPriority0_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_HighPriority0_0_offset 0x00001e00UL
struct QIB_7322_HighPriority0_0_pb {
	pseudo_bit_t Weight[8];
	pseudo_bit_t _unused_0[8];
	pseudo_bit_t VirtualLane[3];
	pseudo_bit_t _unused_1[45];
};
struct QIB_7322_HighPriority0_0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_HighPriority0_0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_CntrRegBase_1_offset 0x00002028UL
/* Default value: 0x0000000000013000 */

#define QIB_7322_ErrMask_1_offset 0x00002080UL
struct QIB_7322_ErrMask_1_pb {
	pseudo_bit_t RcvFormatErrMask[1];
	pseudo_bit_t RcvVCRCErrMask[1];
	pseudo_bit_t RcvICRCErrMask[1];
	pseudo_bit_t RcvMinPktLenErrMask[1];
	pseudo_bit_t RcvMaxPktLenErrMask[1];
	pseudo_bit_t RcvLongPktLenErrMask[1];
	pseudo_bit_t RcvShortPktLenErrMask[1];
	pseudo_bit_t RcvUnexpectedCharErrMask[1];
	pseudo_bit_t RcvUnsupportedVLErrMask[1];
	pseudo_bit_t RcvEBPErrMask[1];
	pseudo_bit_t RcvIBFlowErrMask[1];
	pseudo_bit_t RcvBadVersionErrMask[1];
	pseudo_bit_t _unused_0[2];
	pseudo_bit_t RcvBadTidErrMask[1];
	pseudo_bit_t RcvHdrLenErrMask[1];
	pseudo_bit_t RcvHdrErrMask[1];
	pseudo_bit_t RcvIBLostLinkErrMask[1];
	pseudo_bit_t _unused_1[11];
	pseudo_bit_t SendMinPktLenErrMask[1];
	pseudo_bit_t SendMaxPktLenErrMask[1];
	pseudo_bit_t SendUnderRunErrMask[1];
	pseudo_bit_t SendPktLenErrMask[1];
	pseudo_bit_t SendDroppedSmpPktErrMask[1];
	pseudo_bit_t SendDroppedDataPktErrMask[1];
	pseudo_bit_t _unused_2[1];
	pseudo_bit_t SendUnexpectedPktNumErrMask[1];
	pseudo_bit_t SendUnsupportedVLErrMask[1];
	pseudo_bit_t SendBufMisuseErrMask[1];
	pseudo_bit_t SDmaGenMismatchErrMask[1];
	pseudo_bit_t SDmaOutOfBoundErrMask[1];
	pseudo_bit_t SDmaTailOutOfBoundErrMask[1];
	pseudo_bit_t SDmaBaseErrMask[1];
	pseudo_bit_t SDma1stDescErrMask[1];
	pseudo_bit_t SDmaRpyTagErrMask[1];
	pseudo_bit_t SDmaDwEnErrMask[1];
	pseudo_bit_t SDmaMissingDwErrMask[1];
	pseudo_bit_t SDmaUnexpDataErrMask[1];
	pseudo_bit_t SDmaDescAddrMisalignErrMask[1];
	pseudo_bit_t SDmaHaltErrMask[1];
	pseudo_bit_t _unused_3[4];
	pseudo_bit_t VL15BufMisuseErrMask[1];
	pseudo_bit_t _unused_4[2];
	pseudo_bit_t SHeadersErrMask[1];
	pseudo_bit_t IBStatusChangedMask[1];
	pseudo_bit_t _unused_5[5];
};
struct QIB_7322_ErrMask_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_ErrMask_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_ErrStatus_1_offset 0x00002088UL
struct QIB_7322_ErrStatus_1_pb {
	pseudo_bit_t RcvFormatErr[1];
	pseudo_bit_t RcvVCRCErr[1];
	pseudo_bit_t RcvICRCErr[1];
	pseudo_bit_t RcvMinPktLenErr[1];
	pseudo_bit_t RcvMaxPktLenErr[1];
	pseudo_bit_t RcvLongPktLenErr[1];
	pseudo_bit_t RcvShortPktLenErr[1];
	pseudo_bit_t RcvUnexpectedCharErr[1];
	pseudo_bit_t RcvUnsupportedVLErr[1];
	pseudo_bit_t RcvEBPErr[1];
	pseudo_bit_t RcvIBFlowErr[1];
	pseudo_bit_t RcvBadVersionErr[1];
	pseudo_bit_t _unused_0[2];
	pseudo_bit_t RcvBadTidErr[1];
	pseudo_bit_t RcvHdrLenErr[1];
	pseudo_bit_t RcvHdrErr[1];
	pseudo_bit_t RcvIBLostLinkErr[1];
	pseudo_bit_t _unused_1[11];
	pseudo_bit_t SendMinPktLenErr[1];
	pseudo_bit_t SendMaxPktLenErr[1];
	pseudo_bit_t SendUnderRunErr[1];
	pseudo_bit_t SendPktLenErr[1];
	pseudo_bit_t SendDroppedSmpPktErr[1];
	pseudo_bit_t SendDroppedDataPktErr[1];
	pseudo_bit_t _unused_2[1];
	pseudo_bit_t SendUnexpectedPktNumErr[1];
	pseudo_bit_t SendUnsupportedVLErr[1];
	pseudo_bit_t SendBufMisuseErr[1];
	pseudo_bit_t SDmaGenMismatchErr[1];
	pseudo_bit_t SDmaOutOfBoundErr[1];
	pseudo_bit_t SDmaTailOutOfBoundErr[1];
	pseudo_bit_t SDmaBaseErr[1];
	pseudo_bit_t SDma1stDescErr[1];
	pseudo_bit_t SDmaRpyTagErr[1];
	pseudo_bit_t SDmaDwEnErr[1];
	pseudo_bit_t SDmaMissingDwErr[1];
	pseudo_bit_t SDmaUnexpDataErr[1];
	pseudo_bit_t SDmaDescAddrMisalignErr[1];
	pseudo_bit_t SDmaHaltErr[1];
	pseudo_bit_t _unused_3[4];
	pseudo_bit_t VL15BufMisuseErr[1];
	pseudo_bit_t _unused_4[2];
	pseudo_bit_t SHeadersErr[1];
	pseudo_bit_t IBStatusChanged[1];
	pseudo_bit_t _unused_5[5];
};
struct QIB_7322_ErrStatus_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_ErrStatus_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_ErrClear_1_offset 0x00002090UL
struct QIB_7322_ErrClear_1_pb {
	pseudo_bit_t RcvFormatErrClear[1];
	pseudo_bit_t RcvVCRCErrClear[1];
	pseudo_bit_t RcvICRCErrClear[1];
	pseudo_bit_t RcvMinPktLenErrClear[1];
	pseudo_bit_t RcvMaxPktLenErrClear[1];
	pseudo_bit_t RcvLongPktLenErrClear[1];
	pseudo_bit_t RcvShortPktLenErrClear[1];
	pseudo_bit_t RcvUnexpectedCharErrClear[1];
	pseudo_bit_t RcvUnsupportedVLErrClear[1];
	pseudo_bit_t RcvEBPErrClear[1];
	pseudo_bit_t RcvIBFlowErrClear[1];
	pseudo_bit_t RcvBadVersionErrClear[1];
	pseudo_bit_t _unused_0[2];
	pseudo_bit_t RcvBadTidErrClear[1];
	pseudo_bit_t RcvHdrLenErrClear[1];
	pseudo_bit_t RcvHdrErrClear[1];
	pseudo_bit_t RcvIBLostLinkErrClear[1];
	pseudo_bit_t _unused_1[11];
	pseudo_bit_t SendMinPktLenErrClear[1];
	pseudo_bit_t SendMaxPktLenErrClear[1];
	pseudo_bit_t SendUnderRunErrClear[1];
	pseudo_bit_t SendPktLenErrClear[1];
	pseudo_bit_t SendDroppedSmpPktErrClear[1];
	pseudo_bit_t SendDroppedDataPktErrClear[1];
	pseudo_bit_t _unused_2[1];
	pseudo_bit_t SendUnexpectedPktNumErrClear[1];
	pseudo_bit_t SendUnsupportedVLErrClear[1];
	pseudo_bit_t SendBufMisuseErrClear[1];
	pseudo_bit_t SDmaGenMismatchErrClear[1];
	pseudo_bit_t SDmaOutOfBoundErrClear[1];
	pseudo_bit_t SDmaTailOutOfBoundErrClear[1];
	pseudo_bit_t SDmaBaseErrClear[1];
	pseudo_bit_t SDma1stDescErrClear[1];
	pseudo_bit_t SDmaRpyTagErrClear[1];
	pseudo_bit_t SDmaDwEnErrClear[1];
	pseudo_bit_t SDmaMissingDwErrClear[1];
	pseudo_bit_t SDmaUnexpDataErrClear[1];
	pseudo_bit_t SDmaDescAddrMisalignErrClear[1];
	pseudo_bit_t SDmaHaltErrClear[1];
	pseudo_bit_t _unused_3[4];
	pseudo_bit_t VL15BufMisuseErrClear[1];
	pseudo_bit_t _unused_4[2];
	pseudo_bit_t SHeadersErrClear[1];
	pseudo_bit_t IBStatusChangedClear[1];
	pseudo_bit_t _unused_5[5];
};
struct QIB_7322_ErrClear_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_ErrClear_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_TXEStatus_1_offset 0x000020b8UL
struct QIB_7322_TXEStatus_1_pb {
	pseudo_bit_t LaFifoEmpty_VL0[1];
	pseudo_bit_t LaFifoEmpty_VL1[1];
	pseudo_bit_t LaFifoEmpty_VL2[1];
	pseudo_bit_t LaFifoEmpty_VL3[1];
	pseudo_bit_t LaFifoEmpty_VL4[1];
	pseudo_bit_t LaFifoEmpty_VL5[1];
	pseudo_bit_t LaFifoEmpty_VL6[1];
	pseudo_bit_t LaFifoEmpty_VL7[1];
	pseudo_bit_t _unused_0[7];
	pseudo_bit_t LaFifoEmpty_VL15[1];
	pseudo_bit_t _unused_1[14];
	pseudo_bit_t RmFifoEmpty[1];
	pseudo_bit_t TXE_IBC_Idle[1];
	pseudo_bit_t _unused_2[32];
};
struct QIB_7322_TXEStatus_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_TXEStatus_1_pb );
};
/* Default value: 0x0000000XC00080FF */

#define QIB_7322_RcvCtrl_1_offset 0x00002100UL
struct QIB_7322_RcvCtrl_1_pb {
	pseudo_bit_t _unused_0[1];
	pseudo_bit_t ContextEnableKernel[1];
	pseudo_bit_t ContextEnableUser[16];
	pseudo_bit_t _unused_1[21];
	pseudo_bit_t RcvIBPortEnable[1];
	pseudo_bit_t RcvQPMapEnable[1];
	pseudo_bit_t RcvPartitionKeyDisable[1];
	pseudo_bit_t RcvResetCredit[1];
	pseudo_bit_t _unused_2[21];
};
struct QIB_7322_RcvCtrl_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvCtrl_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvBTHQP_1_offset 0x00002108UL
struct QIB_7322_RcvBTHQP_1_pb {
	pseudo_bit_t RcvBTHQP[24];
	pseudo_bit_t _unused_0[40];
};
struct QIB_7322_RcvBTHQP_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvBTHQP_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvQPMapTableA_1_offset 0x00002110UL
struct QIB_7322_RcvQPMapTableA_1_pb {
	pseudo_bit_t RcvQPMapContext0[5];
	pseudo_bit_t RcvQPMapContext1[5];
	pseudo_bit_t RcvQPMapContext2[5];
	pseudo_bit_t RcvQPMapContext3[5];
	pseudo_bit_t RcvQPMapContext4[5];
	pseudo_bit_t RcvQPMapContext5[5];
	pseudo_bit_t _unused_0[34];
};
struct QIB_7322_RcvQPMapTableA_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvQPMapTableA_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvQPMapTableB_1_offset 0x00002118UL
struct QIB_7322_RcvQPMapTableB_1_pb {
	pseudo_bit_t RcvQPMapContext6[5];
	pseudo_bit_t RcvQPMapContext7[5];
	pseudo_bit_t RcvQPMapContext8[5];
	pseudo_bit_t RcvQPMapContext9[5];
	pseudo_bit_t RcvQPMapContext10[5];
	pseudo_bit_t RcvQPMapContext11[5];
	pseudo_bit_t _unused_0[34];
};
struct QIB_7322_RcvQPMapTableB_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvQPMapTableB_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvQPMapTableC_1_offset 0x00002120UL
struct QIB_7322_RcvQPMapTableC_1_pb {
	pseudo_bit_t RcvQPMapContext12[5];
	pseudo_bit_t RcvQPMapContext13[5];
	pseudo_bit_t RcvQPMapContext14[5];
	pseudo_bit_t RcvQPMapContext15[5];
	pseudo_bit_t RcvQPMapContext16[5];
	pseudo_bit_t RcvQPMapContext17[5];
	pseudo_bit_t _unused_0[34];
};
struct QIB_7322_RcvQPMapTableC_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvQPMapTableC_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvQPMapTableD_1_offset 0x00002128UL
struct QIB_7322_RcvQPMapTableD_1_pb {
	pseudo_bit_t RcvQPMapContext18[5];
	pseudo_bit_t RcvQPMapContext19[5];
	pseudo_bit_t RcvQPMapContext20[5];
	pseudo_bit_t RcvQPMapContext21[5];
	pseudo_bit_t RcvQPMapContext22[5];
	pseudo_bit_t RcvQPMapContext23[5];
	pseudo_bit_t _unused_0[34];
};
struct QIB_7322_RcvQPMapTableD_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvQPMapTableD_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvQPMapTableE_1_offset 0x00002130UL
struct QIB_7322_RcvQPMapTableE_1_pb {
	pseudo_bit_t RcvQPMapContext24[5];
	pseudo_bit_t RcvQPMapContext25[5];
	pseudo_bit_t RcvQPMapContext26[5];
	pseudo_bit_t RcvQPMapContext27[5];
	pseudo_bit_t RcvQPMapContext28[5];
	pseudo_bit_t RcvQPMapContext29[5];
	pseudo_bit_t _unused_0[34];
};
struct QIB_7322_RcvQPMapTableE_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvQPMapTableE_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvQPMapTableF_1_offset 0x00002138UL
struct QIB_7322_RcvQPMapTableF_1_pb {
	pseudo_bit_t RcvQPMapContext30[5];
	pseudo_bit_t RcvQPMapContext31[5];
	pseudo_bit_t _unused_0[54];
};
struct QIB_7322_RcvQPMapTableF_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvQPMapTableF_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_PSStat_1_offset 0x00002140UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_PSStart_1_offset 0x00002148UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_PSInterval_1_offset 0x00002150UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvStatus_1_offset 0x00002160UL
struct QIB_7322_RcvStatus_1_pb {
	pseudo_bit_t RxPktInProgress[1];
	pseudo_bit_t DmaeqBlockingContext[5];
	pseudo_bit_t _unused_0[58];
};
struct QIB_7322_RcvStatus_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvStatus_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvPartitionKey_1_offset 0x00002168UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvQPMulticastContext_1_offset 0x00002170UL
struct QIB_7322_RcvQPMulticastContext_1_pb {
	pseudo_bit_t RcvQpMcContext[5];
	pseudo_bit_t _unused_0[59];
};
struct QIB_7322_RcvQPMulticastContext_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvQPMulticastContext_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvPktLEDCnt_1_offset 0x00002178UL
struct QIB_7322_RcvPktLEDCnt_1_pb {
	pseudo_bit_t OFFperiod[32];
	pseudo_bit_t ONperiod[32];
};
struct QIB_7322_RcvPktLEDCnt_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvPktLEDCnt_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendDmaIdleCnt_1_offset 0x00002180UL
struct QIB_7322_SendDmaIdleCnt_1_pb {
	pseudo_bit_t SendDmaIdleCnt[16];
	pseudo_bit_t _unused_0[48];
};
struct QIB_7322_SendDmaIdleCnt_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SendDmaIdleCnt_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendDmaReloadCnt_1_offset 0x00002188UL
struct QIB_7322_SendDmaReloadCnt_1_pb {
	pseudo_bit_t SendDmaReloadCnt[16];
	pseudo_bit_t _unused_0[48];
};
struct QIB_7322_SendDmaReloadCnt_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SendDmaReloadCnt_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendDmaDescCnt_1_offset 0x00002190UL
struct QIB_7322_SendDmaDescCnt_1_pb {
	pseudo_bit_t SendDmaDescCnt[16];
	pseudo_bit_t _unused_0[48];
};
struct QIB_7322_SendDmaDescCnt_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SendDmaDescCnt_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendCtrl_1_offset 0x000021c0UL
struct QIB_7322_SendCtrl_1_pb {
	pseudo_bit_t TxeAbortIbc[1];
	pseudo_bit_t TxeBypassIbc[1];
	pseudo_bit_t _unused_0[1];
	pseudo_bit_t SendEnable[1];
	pseudo_bit_t _unused_1[3];
	pseudo_bit_t ForceCreditUpToDate[1];
	pseudo_bit_t SDmaCleanup[1];
	pseudo_bit_t SDmaIntEnable[1];
	pseudo_bit_t SDmaSingleDescriptor[1];
	pseudo_bit_t SDmaEnable[1];
	pseudo_bit_t SDmaHalt[1];
	pseudo_bit_t TxeDrainLaFifo[1];
	pseudo_bit_t TxeDrainRmFifo[1];
	pseudo_bit_t IBVLArbiterEn[1];
	pseudo_bit_t _unused_2[48];
};
struct QIB_7322_SendCtrl_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SendCtrl_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendDmaBase_1_offset 0x000021f8UL
struct QIB_7322_SendDmaBase_1_pb {
	pseudo_bit_t SendDmaBase[48];
	pseudo_bit_t _unused_0[16];
};
struct QIB_7322_SendDmaBase_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SendDmaBase_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendDmaLenGen_1_offset 0x00002200UL
struct QIB_7322_SendDmaLenGen_1_pb {
	pseudo_bit_t Length[16];
	pseudo_bit_t Generation[3];
	pseudo_bit_t _unused_0[45];
};
struct QIB_7322_SendDmaLenGen_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SendDmaLenGen_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendDmaTail_1_offset 0x00002208UL
struct QIB_7322_SendDmaTail_1_pb {
	pseudo_bit_t SendDmaTail[16];
	pseudo_bit_t _unused_0[48];
};
struct QIB_7322_SendDmaTail_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SendDmaTail_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendDmaHead_1_offset 0x00002210UL
struct QIB_7322_SendDmaHead_1_pb {
	pseudo_bit_t SendDmaHead[16];
	pseudo_bit_t _unused_0[16];
	pseudo_bit_t InternalSendDmaHead[16];
	pseudo_bit_t _unused_1[16];
};
struct QIB_7322_SendDmaHead_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SendDmaHead_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendDmaHeadAddr_1_offset 0x00002218UL
struct QIB_7322_SendDmaHeadAddr_1_pb {
	pseudo_bit_t SendDmaHeadAddr[48];
	pseudo_bit_t _unused_0[16];
};
struct QIB_7322_SendDmaHeadAddr_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SendDmaHeadAddr_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendDmaBufMask0_1_offset 0x00002220UL
struct QIB_7322_SendDmaBufMask0_1_pb {
	pseudo_bit_t BufMask_63_0[64];
};
struct QIB_7322_SendDmaBufMask0_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SendDmaBufMask0_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendDmaStatus_1_offset 0x00002238UL
struct QIB_7322_SendDmaStatus_1_pb {
	pseudo_bit_t SplFifoDescIndex[16];
	pseudo_bit_t SplFifoBufNum[8];
	pseudo_bit_t SplFifoFull[1];
	pseudo_bit_t SplFifoEmpty[1];
	pseudo_bit_t SplFifoDisarmed[1];
	pseudo_bit_t SplFifoReadyToGo[1];
	pseudo_bit_t ScbFetchDescFlag[1];
	pseudo_bit_t ScbEntryValid[1];
	pseudo_bit_t ScbEmpty[1];
	pseudo_bit_t ScbFull[1];
	pseudo_bit_t RpyTag_7_0[8];
	pseudo_bit_t RpyLowAddr_6_0[7];
	pseudo_bit_t ScbDescIndex_13_0[14];
	pseudo_bit_t InternalSDmaHalt[1];
	pseudo_bit_t HaltInProg[1];
	pseudo_bit_t ScoreBoardDrainInProg[1];
};
struct QIB_7322_SendDmaStatus_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SendDmaStatus_1_pb );
};
/* Default value: 0x0000000042000000 */

#define QIB_7322_SendDmaPriorityThld_1_offset 0x00002258UL
struct QIB_7322_SendDmaPriorityThld_1_pb {
	pseudo_bit_t PriorityThreshold[4];
	pseudo_bit_t _unused_0[60];
};
struct QIB_7322_SendDmaPriorityThld_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SendDmaPriorityThld_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendHdrErrSymptom_1_offset 0x00002260UL
struct QIB_7322_SendHdrErrSymptom_1_pb {
	pseudo_bit_t PacketTooSmall[1];
	pseudo_bit_t RawIPV6[1];
	pseudo_bit_t SLIDFail[1];
	pseudo_bit_t QPFail[1];
	pseudo_bit_t PkeyFail[1];
	pseudo_bit_t GRHFail[1];
	pseudo_bit_t NonKeyPacket[1];
	pseudo_bit_t _unused_0[57];
};
struct QIB_7322_SendHdrErrSymptom_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SendHdrErrSymptom_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxCreditVL0_1_offset 0x00002280UL
struct QIB_7322_RxCreditVL0_1_pb {
	pseudo_bit_t RxMaxCreditVL[12];
	pseudo_bit_t _unused_0[4];
	pseudo_bit_t RxBufrConsumedVL[12];
	pseudo_bit_t _unused_1[36];
};
struct QIB_7322_RxCreditVL0_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxCreditVL0_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendDmaBufUsed0_1_offset 0x00002480UL
struct QIB_7322_SendDmaBufUsed0_1_pb {
	pseudo_bit_t BufUsed_63_0[64];
};
struct QIB_7322_SendDmaBufUsed0_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SendDmaBufUsed0_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendDmaReqTagUsed_1_offset 0x00002498UL
struct QIB_7322_SendDmaReqTagUsed_1_pb {
	pseudo_bit_t ReqTagUsed_7_0[8];
	pseudo_bit_t _unused_0[56];
};
struct QIB_7322_SendDmaReqTagUsed_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SendDmaReqTagUsed_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendCheckControl_1_offset 0x000024a8UL
struct QIB_7322_SendCheckControl_1_pb {
	pseudo_bit_t PacketTooSmall_En[1];
	pseudo_bit_t RawIPV6_En[1];
	pseudo_bit_t SLID_En[1];
	pseudo_bit_t BTHQP_En[1];
	pseudo_bit_t PKey_En[1];
	pseudo_bit_t _unused_0[59];
};
struct QIB_7322_SendCheckControl_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SendCheckControl_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendIBSLIDMask_1_offset 0x000024b0UL
struct QIB_7322_SendIBSLIDMask_1_pb {
	pseudo_bit_t SendIBSLIDMask_15_0[16];
	pseudo_bit_t _unused_0[48];
};
struct QIB_7322_SendIBSLIDMask_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SendIBSLIDMask_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendIBSLIDAssign_1_offset 0x000024b8UL
struct QIB_7322_SendIBSLIDAssign_1_pb {
	pseudo_bit_t SendIBSLIDAssign_15_0[16];
	pseudo_bit_t _unused_0[48];
};
struct QIB_7322_SendIBSLIDAssign_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SendIBSLIDAssign_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_IBCStatusA_1_offset 0x00002540UL
struct QIB_7322_IBCStatusA_1_pb {
	pseudo_bit_t LinkTrainingState[5];
	pseudo_bit_t LinkState[3];
	pseudo_bit_t LinkSpeedActive[1];
	pseudo_bit_t LinkWidthActive[1];
	pseudo_bit_t DDS_RXEQ_FAIL[1];
	pseudo_bit_t _unused_0[1];
	pseudo_bit_t IBRxLaneReversed[1];
	pseudo_bit_t IBTxLaneReversed[1];
	pseudo_bit_t ScrambleEn[1];
	pseudo_bit_t ScrambleCapRemote[1];
	pseudo_bit_t _unused_1[13];
	pseudo_bit_t LinkSpeedQDR[1];
	pseudo_bit_t TxReady[1];
	pseudo_bit_t _unused_2[1];
	pseudo_bit_t TxCreditOk_VL0[1];
	pseudo_bit_t TxCreditOk_VL1[1];
	pseudo_bit_t TxCreditOk_VL2[1];
	pseudo_bit_t TxCreditOk_VL3[1];
	pseudo_bit_t TxCreditOk_VL4[1];
	pseudo_bit_t TxCreditOk_VL5[1];
	pseudo_bit_t TxCreditOk_VL6[1];
	pseudo_bit_t TxCreditOk_VL7[1];
	pseudo_bit_t _unused_3[24];
};
struct QIB_7322_IBCStatusA_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_IBCStatusA_1_pb );
};
/* Default value: 0x0000000000000X02 */

#define QIB_7322_IBCStatusB_1_offset 0x00002548UL
struct QIB_7322_IBCStatusB_1_pb {
	pseudo_bit_t LinkRoundTripLatency[26];
	pseudo_bit_t ReqDDSLocalFromRmt[4];
	pseudo_bit_t RxEqLocalDevice[2];
	pseudo_bit_t heartbeat_crosstalk[4];
	pseudo_bit_t heartbeat_timed_out[1];
	pseudo_bit_t _unused_0[27];
};
struct QIB_7322_IBCStatusB_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_IBCStatusB_1_pb );
};
/* Default value: 0x00000000XXXXXXXX */

#define QIB_7322_IBCCtrlA_1_offset 0x00002560UL
struct QIB_7322_IBCCtrlA_1_pb {
	pseudo_bit_t FlowCtrlPeriod[8];
	pseudo_bit_t FlowCtrlWaterMark[8];
	pseudo_bit_t LinkInitCmd[3];
	pseudo_bit_t LinkCmd[2];
	pseudo_bit_t MaxPktLen[11];
	pseudo_bit_t PhyerrThreshold[4];
	pseudo_bit_t OverrunThreshold[4];
	pseudo_bit_t _unused_0[8];
	pseudo_bit_t NumVLane[3];
	pseudo_bit_t _unused_1[9];
	pseudo_bit_t IBStatIntReductionEn[1];
	pseudo_bit_t IBLinkEn[1];
	pseudo_bit_t LinkDownDefaultState[1];
	pseudo_bit_t Loopback[1];
};
struct QIB_7322_IBCCtrlA_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_IBCCtrlA_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_IBCCtrlB_1_offset 0x00002568UL
struct QIB_7322_IBCCtrlB_1_pb {
	pseudo_bit_t IB_ENHANCED_MODE[1];
	pseudo_bit_t SD_SPEED[1];
	pseudo_bit_t SD_SPEED_SDR[1];
	pseudo_bit_t SD_SPEED_DDR[1];
	pseudo_bit_t SD_SPEED_QDR[1];
	pseudo_bit_t IB_NUM_CHANNELS[2];
	pseudo_bit_t IB_POLARITY_REV_SUPP[1];
	pseudo_bit_t IB_LANE_REV_SUPPORTED[1];
	pseudo_bit_t SD_RX_EQUAL_ENABLE[1];
	pseudo_bit_t SD_ADD_ENB[1];
	pseudo_bit_t SD_DDSV[1];
	pseudo_bit_t SD_DDS[4];
	pseudo_bit_t HRTBT_ENB[1];
	pseudo_bit_t HRTBT_AUTO[1];
	pseudo_bit_t HRTBT_PORT[8];
	pseudo_bit_t HRTBT_REQ[1];
	pseudo_bit_t IB_ENABLE_FILT_DPKT[1];
	pseudo_bit_t _unused_0[4];
	pseudo_bit_t IB_DLID[16];
	pseudo_bit_t IB_DLID_MASK[16];
};
struct QIB_7322_IBCCtrlB_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_IBCCtrlB_1_pb );
};
/* Default value: 0x00000000000305FF */

#define QIB_7322_IBCCtrlC_1_offset 0x00002570UL
struct QIB_7322_IBCCtrlC_1_pb {
	pseudo_bit_t IB_FRONT_PORCH[5];
	pseudo_bit_t IB_BACK_PORCH[5];
	pseudo_bit_t _unused_0[54];
};
struct QIB_7322_IBCCtrlC_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_IBCCtrlC_1_pb );
};
/* Default value: 0x0000000000000301 */

#define QIB_7322_HRTBT_GUID_1_offset 0x00002588UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_IB_SDTEST_IF_TX_1_offset 0x00002590UL
struct QIB_7322_IB_SDTEST_IF_TX_1_pb {
	pseudo_bit_t TS_T_TX_VALID[1];
	pseudo_bit_t TS_3_TX_VALID[1];
	pseudo_bit_t VL_CAP[2];
	pseudo_bit_t CREDIT_CHANGE[1];
	pseudo_bit_t _unused_0[6];
	pseudo_bit_t TS_TX_OPCODE[2];
	pseudo_bit_t TS_TX_SPEED[3];
	pseudo_bit_t _unused_1[16];
	pseudo_bit_t TS_TX_TX_CFG[16];
	pseudo_bit_t TS_TX_RX_CFG[16];
};
struct QIB_7322_IB_SDTEST_IF_TX_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_IB_SDTEST_IF_TX_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_IB_SDTEST_IF_RX_1_offset 0x00002598UL
struct QIB_7322_IB_SDTEST_IF_RX_1_pb {
	pseudo_bit_t TS_T_RX_VALID[1];
	pseudo_bit_t TS_3_RX_VALID[1];
	pseudo_bit_t _unused_0[14];
	pseudo_bit_t TS_RX_A[8];
	pseudo_bit_t TS_RX_B[8];
	pseudo_bit_t TS_RX_TX_CFG[16];
	pseudo_bit_t TS_RX_RX_CFG[16];
};
struct QIB_7322_IB_SDTEST_IF_RX_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_IB_SDTEST_IF_RX_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_IBNCModeCtrl_1_offset 0x000025b8UL
struct QIB_7322_IBNCModeCtrl_1_pb {
	pseudo_bit_t TSMEnable_send_TS1[1];
	pseudo_bit_t TSMEnable_send_TS2[1];
	pseudo_bit_t TSMEnable_ignore_TSM_on_rx[1];
	pseudo_bit_t _unused_0[5];
	pseudo_bit_t TSMCode_TS1[9];
	pseudo_bit_t TSMCode_TS2[9];
	pseudo_bit_t _unused_1[6];
	pseudo_bit_t ScrambleCapLocal[1];
	pseudo_bit_t ScrambleCapRemoteMask[1];
	pseudo_bit_t ScrambleCapRemoteForce[1];
	pseudo_bit_t _unused_2[29];
};
struct QIB_7322_IBNCModeCtrl_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_IBNCModeCtrl_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_IBSerdesStatus_1_offset 0x000025d0UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_IBPCSConfig_1_offset 0x000025d8UL
struct QIB_7322_IBPCSConfig_1_pb {
	pseudo_bit_t tx_rx_reset[1];
	pseudo_bit_t xcv_treset[1];
	pseudo_bit_t xcv_rreset[1];
	pseudo_bit_t _unused_0[6];
	pseudo_bit_t link_sync_mask[10];
	pseudo_bit_t _unused_1[45];
};
struct QIB_7322_IBPCSConfig_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_IBPCSConfig_1_pb );
};
/* Default value: 0x0000000000000007 */

#define QIB_7322_IBSerdesCtrl_1_offset 0x000025e0UL
struct QIB_7322_IBSerdesCtrl_1_pb {
	pseudo_bit_t CMODE[7];
	pseudo_bit_t _unused_0[1];
	pseudo_bit_t TXIDLE[1];
	pseudo_bit_t RXPD[1];
	pseudo_bit_t TXPD[1];
	pseudo_bit_t PLLPD[1];
	pseudo_bit_t LPEN[1];
	pseudo_bit_t RXLOSEN[1];
	pseudo_bit_t _unused_1[1];
	pseudo_bit_t IB_LAT_MODE[1];
	pseudo_bit_t CGMODE[4];
	pseudo_bit_t CHANNEL_RESET_N[4];
	pseudo_bit_t DISABLE_RXLATOFF_SDR[1];
	pseudo_bit_t DISABLE_RXLATOFF_DDR[1];
	pseudo_bit_t DISABLE_RXLATOFF_QDR[1];
	pseudo_bit_t _unused_2[37];
};
struct QIB_7322_IBSerdesCtrl_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_IBSerdesCtrl_1_pb );
};
/* Default value: 0x0000000000FFA00F */

#define QIB_7322_IBSD_TX_DEEMPHASIS_OVERRIDE_1_offset 0x00002600UL
struct QIB_7322_IBSD_TX_DEEMPHASIS_OVERRIDE_1_pb {
	pseudo_bit_t txcn1_ena[3];
	pseudo_bit_t txcn1_xtra_emph0[2];
	pseudo_bit_t txcp1_ena[4];
	pseudo_bit_t txc0_ena[5];
	pseudo_bit_t txampcntl_d2a[4];
	pseudo_bit_t _unused_0[12];
	pseudo_bit_t reset_tx_deemphasis_override[1];
	pseudo_bit_t tx_override_deemphasis_select[1];
	pseudo_bit_t _unused_1[32];
};
struct QIB_7322_IBSD_TX_DEEMPHASIS_OVERRIDE_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_IBSD_TX_DEEMPHASIS_OVERRIDE_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_ADAPT_DISABLE_STATIC_SDR_1_offset 0x00002640UL
struct QIB_7322_ADAPT_DISABLE_STATIC_SDR_1_pb {
	pseudo_bit_t static_disable_rxenadfe_sdr_ch0[8];
	pseudo_bit_t static_disable_rxenadfe_sdr_ch1[8];
	pseudo_bit_t static_disable_rxenadfe_sdr_ch2[8];
	pseudo_bit_t static_disable_rxenadfe_sdr_ch3[8];
	pseudo_bit_t static_disable_rxenale_sdr_ch0[1];
	pseudo_bit_t static_disable_rxenale_sdr_ch1[1];
	pseudo_bit_t static_disable_rxenale_sdr_ch2[1];
	pseudo_bit_t static_disable_rxenale_sdr_ch3[1];
	pseudo_bit_t static_disable_rxenagain_sdr_ch0[1];
	pseudo_bit_t static_disable_rxenagain_sdr_ch1[1];
	pseudo_bit_t static_disable_rxenagain_sdr_ch2[1];
	pseudo_bit_t static_disable_rxenagain_sdr_ch3[1];
	pseudo_bit_t _unused_0[24];
};
struct QIB_7322_ADAPT_DISABLE_STATIC_SDR_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_ADAPT_DISABLE_STATIC_SDR_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_ADAPT_DISABLE_DYNAMIC_SDR_1_offset 0x00002648UL
struct QIB_7322_ADAPT_DISABLE_DYNAMIC_SDR_1_pb {
	pseudo_bit_t dyn_disable_rxenadfe_sdr_ch0[8];
	pseudo_bit_t dyn_disable_rxenadfe_sdr_ch1[8];
	pseudo_bit_t dyn_disable_rxenadfe_sdr_ch2[8];
	pseudo_bit_t dyn_disable_rxenadfe_sdr_ch3[8];
	pseudo_bit_t dyn_disable_rxenale_sdr_ch0[1];
	pseudo_bit_t dyn_disable_rxenale_sdr_ch1[1];
	pseudo_bit_t dyn_disable_rxenale_sdr_ch2[1];
	pseudo_bit_t dyn_disable_rxenale_sdr_ch3[1];
	pseudo_bit_t dyn_disable_rxenagain_sdr_ch0[1];
	pseudo_bit_t dyn_disable_rxenagain_sdr_ch1[1];
	pseudo_bit_t dyn_disable_rxenagain_sdr_ch2[1];
	pseudo_bit_t dyn_disable_rxenagain_sdr_ch3[1];
	pseudo_bit_t _unused_0[24];
};
struct QIB_7322_ADAPT_DISABLE_DYNAMIC_SDR_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_ADAPT_DISABLE_DYNAMIC_SDR_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_ADAPT_DISABLE_STATIC_DDR_1_offset 0x00002650UL
struct QIB_7322_ADAPT_DISABLE_STATIC_DDR_1_pb {
	pseudo_bit_t static_disable_rxenadfe_ddr_ch0[8];
	pseudo_bit_t static_disable_rxenadfe_ddr_ch1[8];
	pseudo_bit_t static_disable_rxenadfe_ddr_ch2[8];
	pseudo_bit_t static_disable_rxenadfe_ddr_ch3[8];
	pseudo_bit_t static_disable_rxenale_ddr_ch0[1];
	pseudo_bit_t static_disable_rxenale_ddr_ch1[1];
	pseudo_bit_t static_disable_rxenale_ddr_ch2[1];
	pseudo_bit_t static_disable_rxenale_ddr_ch3[1];
	pseudo_bit_t static_disable_rxenagain_ddr_ch0[1];
	pseudo_bit_t static_disable_rxenagain_ddr_ch1[1];
	pseudo_bit_t static_disable_rxenagain_ddr_ch2[1];
	pseudo_bit_t static_disable_rxenagain_ddr_ch3[1];
	pseudo_bit_t _unused_0[24];
};
struct QIB_7322_ADAPT_DISABLE_STATIC_DDR_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_ADAPT_DISABLE_STATIC_DDR_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_ADAPT_DISABLE_DYNAMIC_DDR_1_offset 0x00002658UL
struct QIB_7322_ADAPT_DISABLE_DYNAMIC_DDR_1_pb {
	pseudo_bit_t dyn_disable_rxenadfe_ddr_ch0[8];
	pseudo_bit_t dyn_disable_rxenadfe_ddr_ch1[8];
	pseudo_bit_t dyn_disable_rxenadfe_ddr_ch2[8];
	pseudo_bit_t dyn_disable_rxenadfe_ddr_ch3[8];
	pseudo_bit_t dyn_disable_rxenale_ddr_ch0[1];
	pseudo_bit_t dyn_disable_rxenale_ddr_ch1[1];
	pseudo_bit_t dyn_disable_rxenale_ddr_ch2[1];
	pseudo_bit_t dyn_disable_rxenale_ddr_ch3[1];
	pseudo_bit_t dyn_disable_rxenagain_ddr_ch0[1];
	pseudo_bit_t dyn_disable_rxenagain_ddr_ch1[1];
	pseudo_bit_t dyn_disable_rxenagain_ddr_ch2[1];
	pseudo_bit_t dyn_disable_rxenagain_ddr_ch3[1];
	pseudo_bit_t _unused_0[24];
};
struct QIB_7322_ADAPT_DISABLE_DYNAMIC_DDR_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_ADAPT_DISABLE_DYNAMIC_DDR_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_ADAPT_DISABLE_STATIC_QDR_1_offset 0x00002660UL
struct QIB_7322_ADAPT_DISABLE_STATIC_QDR_1_pb {
	pseudo_bit_t static_disable_rxenadfe_qdr_ch0[8];
	pseudo_bit_t static_disable_rxenadfe_qdr_ch1[8];
	pseudo_bit_t static_disable_rxenadfe_qdr_ch2[8];
	pseudo_bit_t static_disable_rxenadfe_qdr_ch3[8];
	pseudo_bit_t static_disable_rxenale_qdr_ch0[1];
	pseudo_bit_t static_disable_rxenale_qdr_ch1[1];
	pseudo_bit_t static_disable_rxenale_qdr_ch2[1];
	pseudo_bit_t static_disable_rxenale_qdr_ch3[1];
	pseudo_bit_t static_disable_rxenagain_qdr_ch0[1];
	pseudo_bit_t static_disable_rxenagain_qdr_ch1[1];
	pseudo_bit_t static_disable_rxenagain_qdr_ch2[1];
	pseudo_bit_t static_disable_rxenagain_qdr_ch3[1];
	pseudo_bit_t _unused_0[24];
};
struct QIB_7322_ADAPT_DISABLE_STATIC_QDR_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_ADAPT_DISABLE_STATIC_QDR_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_ADAPT_DISABLE_DYNAMIC_QDR_1_offset 0x00002668UL
struct QIB_7322_ADAPT_DISABLE_DYNAMIC_QDR_1_pb {
	pseudo_bit_t dyn_disable_rxenadfe_qdr_ch0[8];
	pseudo_bit_t dyn_disable_rxenadfe_qdr_ch1[8];
	pseudo_bit_t dyn_disable_rxenadfe_qdr_ch2[8];
	pseudo_bit_t dyn_disable_rxenadfe_qdr_ch3[8];
	pseudo_bit_t dyn_disable_rxenale_qdr_ch0[1];
	pseudo_bit_t dyn_disable_rxenale_qdr_ch1[1];
	pseudo_bit_t dyn_disable_rxenale_qdr_ch2[1];
	pseudo_bit_t dyn_disable_rxenale_qdr_ch3[1];
	pseudo_bit_t dyn_disable_rxenagain_qdr_ch0[1];
	pseudo_bit_t dyn_disable_rxenagain_qdr_ch1[1];
	pseudo_bit_t dyn_disable_rxenagain_qdr_ch2[1];
	pseudo_bit_t dyn_disable_rxenagain_qdr_ch3[1];
	pseudo_bit_t _unused_0[24];
};
struct QIB_7322_ADAPT_DISABLE_DYNAMIC_QDR_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_ADAPT_DISABLE_DYNAMIC_QDR_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_ADAPT_DISABLE_TIMER_THRESHOLD_1_offset 0x00002670UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxBufrUnCorErrLogA_1_offset 0x00002800UL
struct QIB_7322_RxBufrUnCorErrLogA_1_pb {
	pseudo_bit_t RxBufrUnCorErrData_63_0[64];
};
struct QIB_7322_RxBufrUnCorErrLogA_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxBufrUnCorErrLogA_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxBufrUnCorErrLogB_1_offset 0x00002808UL
struct QIB_7322_RxBufrUnCorErrLogB_1_pb {
	pseudo_bit_t RxBufrUnCorErrData_127_64[64];
};
struct QIB_7322_RxBufrUnCorErrLogB_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxBufrUnCorErrLogB_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxBufrUnCorErrLogC_1_offset 0x00002810UL
struct QIB_7322_RxBufrUnCorErrLogC_1_pb {
	pseudo_bit_t RxBufrUnCorErrData_191_128[64];
};
struct QIB_7322_RxBufrUnCorErrLogC_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxBufrUnCorErrLogC_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxBufrUnCorErrLogD_1_offset 0x00002818UL
struct QIB_7322_RxBufrUnCorErrLogD_1_pb {
	pseudo_bit_t RxBufrUnCorErrData_255_192[64];
};
struct QIB_7322_RxBufrUnCorErrLogD_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxBufrUnCorErrLogD_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxBufrUnCorErrLogE_1_offset 0x00002820UL
struct QIB_7322_RxBufrUnCorErrLogE_1_pb {
	pseudo_bit_t RxBufrUnCorErrData_258_256[3];
	pseudo_bit_t RxBufrUnCorErrCheckBit_36_0[37];
	pseudo_bit_t RxBufrUnCorErrAddr_15_0[16];
	pseudo_bit_t _unused_0[8];
};
struct QIB_7322_RxBufrUnCorErrLogE_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxBufrUnCorErrLogE_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxFlagUnCorErrLogA_1_offset 0x00002828UL
struct QIB_7322_RxFlagUnCorErrLogA_1_pb {
	pseudo_bit_t RxFlagUnCorErrData_63_0[64];
};
struct QIB_7322_RxFlagUnCorErrLogA_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxFlagUnCorErrLogA_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxFlagUnCorErrLogB_1_offset 0x00002830UL
struct QIB_7322_RxFlagUnCorErrLogB_1_pb {
	pseudo_bit_t RxFlagUnCorErrCheckBit_7_0[8];
	pseudo_bit_t RxFlagUnCorErrAddr_12_0[13];
	pseudo_bit_t _unused_0[43];
};
struct QIB_7322_RxFlagUnCorErrLogB_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxFlagUnCorErrLogB_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxLkupiqUnCorErrLogA_1_offset 0x00002840UL
struct QIB_7322_RxLkupiqUnCorErrLogA_1_pb {
	pseudo_bit_t RxLkupiqUnCorErrData_45_0[46];
	pseudo_bit_t RxLkupiqUnCorErrCheckBit_7_0[8];
	pseudo_bit_t _unused_0[10];
};
struct QIB_7322_RxLkupiqUnCorErrLogA_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxLkupiqUnCorErrLogA_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxLkupiqUnCorErrLogB_1_offset 0x00002848UL
struct QIB_7322_RxLkupiqUnCorErrLogB_1_pb {
	pseudo_bit_t RxLkupiqUnCorErrAddr_12_0[13];
	pseudo_bit_t _unused_0[51];
};
struct QIB_7322_RxLkupiqUnCorErrLogB_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxLkupiqUnCorErrLogB_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxHdrFifoUnCorErrLogA_1_offset 0x00002850UL
struct QIB_7322_RxHdrFifoUnCorErrLogA_1_pb {
	pseudo_bit_t RxHdrFifoUnCorErrData_63_0[64];
};
struct QIB_7322_RxHdrFifoUnCorErrLogA_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxHdrFifoUnCorErrLogA_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxHdrFifoUnCorErrLogB_1_offset 0x00002858UL
struct QIB_7322_RxHdrFifoUnCorErrLogB_1_pb {
	pseudo_bit_t RxHdrFifoUnCorErrData_127_64[64];
};
struct QIB_7322_RxHdrFifoUnCorErrLogB_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxHdrFifoUnCorErrLogB_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxHdrFifoUnCorErrLogC_1_offset 0x00002860UL
struct QIB_7322_RxHdrFifoUnCorErrLogC_1_pb {
	pseudo_bit_t RxHdrFifoUnCorErrCheckBit_15_0[16];
	pseudo_bit_t RxHdrFifoUnCorErrAddr_10_0[11];
	pseudo_bit_t _unused_0[37];
};
struct QIB_7322_RxHdrFifoUnCorErrLogC_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxHdrFifoUnCorErrLogC_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxDataFifoUnCorErrLogA_1_offset 0x00002868UL
struct QIB_7322_RxDataFifoUnCorErrLogA_1_pb {
	pseudo_bit_t RxDataFifoUnCorErrData_63_0[64];
};
struct QIB_7322_RxDataFifoUnCorErrLogA_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxDataFifoUnCorErrLogA_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxDataFifoUnCorErrLogB_1_offset 0x00002870UL
struct QIB_7322_RxDataFifoUnCorErrLogB_1_pb {
	pseudo_bit_t RxDataFifoUnCorErrData_127_64[64];
};
struct QIB_7322_RxDataFifoUnCorErrLogB_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxDataFifoUnCorErrLogB_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxDataFifoUnCorErrLogC_1_offset 0x00002878UL
struct QIB_7322_RxDataFifoUnCorErrLogC_1_pb {
	pseudo_bit_t RxDataFifoUnCorErrCheckBit_15_0[16];
	pseudo_bit_t RxDataFifoUnCorErrAddr_10_0[11];
	pseudo_bit_t _unused_0[37];
};
struct QIB_7322_RxDataFifoUnCorErrLogC_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxDataFifoUnCorErrLogC_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_LaFifoArray0UnCorErrLog_1_offset 0x00002880UL
struct QIB_7322_LaFifoArray0UnCorErrLog_1_pb {
	pseudo_bit_t LaFifoArray0UnCorErrData_34_0[35];
	pseudo_bit_t LaFifoArray0UnCorErrCheckBit_10_0[11];
	pseudo_bit_t LaFifoArray0UnCorErrAddr_10_0[11];
	pseudo_bit_t _unused_0[7];
};
struct QIB_7322_LaFifoArray0UnCorErrLog_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_LaFifoArray0UnCorErrLog_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RmFifoArrayUnCorErrLogA_1_offset 0x000028c0UL
struct QIB_7322_RmFifoArrayUnCorErrLogA_1_pb {
	pseudo_bit_t RmFifoArrayUnCorErrData_63_0[64];
};
struct QIB_7322_RmFifoArrayUnCorErrLogA_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RmFifoArrayUnCorErrLogA_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RmFifoArrayUnCorErrLogB_1_offset 0x000028c8UL
struct QIB_7322_RmFifoArrayUnCorErrLogB_1_pb {
	pseudo_bit_t RmFifoArrayUnCorErrData_127_64[64];
};
struct QIB_7322_RmFifoArrayUnCorErrLogB_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RmFifoArrayUnCorErrLogB_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RmFifoArrayUnCorErrLogC_1_offset 0x000028d0UL
struct QIB_7322_RmFifoArrayUnCorErrLogC_1_pb {
	pseudo_bit_t RmFifoArrayUnCorErrCheckBit_27_0[28];
	pseudo_bit_t RmFifoArrayUnCorErrAddr_13_0[14];
	pseudo_bit_t _unused_0[18];
	pseudo_bit_t RmFifoArrayUnCorErrDword_3_0[4];
};
struct QIB_7322_RmFifoArrayUnCorErrLogC_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RmFifoArrayUnCorErrLogC_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxBufrCorErrLogA_1_offset 0x00002900UL
struct QIB_7322_RxBufrCorErrLogA_1_pb {
	pseudo_bit_t RxBufrCorErrData_63_0[64];
};
struct QIB_7322_RxBufrCorErrLogA_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxBufrCorErrLogA_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxBufrCorErrLogB_1_offset 0x00002908UL
struct QIB_7322_RxBufrCorErrLogB_1_pb {
	pseudo_bit_t RxBufrCorErrData_127_64[64];
};
struct QIB_7322_RxBufrCorErrLogB_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxBufrCorErrLogB_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxBufrCorErrLogC_1_offset 0x00002910UL
struct QIB_7322_RxBufrCorErrLogC_1_pb {
	pseudo_bit_t RxBufrCorErrData_191_128[64];
};
struct QIB_7322_RxBufrCorErrLogC_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxBufrCorErrLogC_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxBufrCorErrLogD_1_offset 0x00002918UL
struct QIB_7322_RxBufrCorErrLogD_1_pb {
	pseudo_bit_t RxBufrCorErrData_255_192[64];
};
struct QIB_7322_RxBufrCorErrLogD_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxBufrCorErrLogD_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxBufrCorErrLogE_1_offset 0x00002920UL
struct QIB_7322_RxBufrCorErrLogE_1_pb {
	pseudo_bit_t RxBufrCorErrData_258_256[3];
	pseudo_bit_t RxBufrCorErrCheckBit_36_0[37];
	pseudo_bit_t RxBufrCorErrAddr_15_0[16];
	pseudo_bit_t _unused_0[8];
};
struct QIB_7322_RxBufrCorErrLogE_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxBufrCorErrLogE_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxFlagCorErrLogA_1_offset 0x00002928UL
struct QIB_7322_RxFlagCorErrLogA_1_pb {
	pseudo_bit_t RxFlagCorErrData_63_0[64];
};
struct QIB_7322_RxFlagCorErrLogA_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxFlagCorErrLogA_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxFlagCorErrLogB_1_offset 0x00002930UL
struct QIB_7322_RxFlagCorErrLogB_1_pb {
	pseudo_bit_t RxFlagCorErrCheckBit_7_0[8];
	pseudo_bit_t RxFlagCorErrAddr_12_0[13];
	pseudo_bit_t _unused_0[43];
};
struct QIB_7322_RxFlagCorErrLogB_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxFlagCorErrLogB_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxLkupiqCorErrLogA_1_offset 0x00002940UL
struct QIB_7322_RxLkupiqCorErrLogA_1_pb {
	pseudo_bit_t RxLkupiqCorErrData_45_0[46];
	pseudo_bit_t RxLkupiqCorErrCheckBit_7_0[8];
	pseudo_bit_t _unused_0[10];
};
struct QIB_7322_RxLkupiqCorErrLogA_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxLkupiqCorErrLogA_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxLkupiqCorErrLogB_1_offset 0x00002948UL
struct QIB_7322_RxLkupiqCorErrLogB_1_pb {
	pseudo_bit_t RxLkupiqCorErrAddr_12_0[13];
	pseudo_bit_t _unused_0[51];
};
struct QIB_7322_RxLkupiqCorErrLogB_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxLkupiqCorErrLogB_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxHdrFifoCorErrLogA_1_offset 0x00002950UL
struct QIB_7322_RxHdrFifoCorErrLogA_1_pb {
	pseudo_bit_t RxHdrFifoCorErrData_63_0[64];
};
struct QIB_7322_RxHdrFifoCorErrLogA_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxHdrFifoCorErrLogA_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxHdrFifoCorErrLogB_1_offset 0x00002958UL
struct QIB_7322_RxHdrFifoCorErrLogB_1_pb {
	pseudo_bit_t RxHdrFifoCorErrData_127_64[64];
};
struct QIB_7322_RxHdrFifoCorErrLogB_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxHdrFifoCorErrLogB_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxHdrFifoCorErrLogC_1_offset 0x00002960UL
struct QIB_7322_RxHdrFifoCorErrLogC_1_pb {
	pseudo_bit_t RxHdrFifoCorErrCheckBit_15_0[16];
	pseudo_bit_t RxHdrFifoCorErrAddr_10_0[11];
	pseudo_bit_t _unused_0[37];
};
struct QIB_7322_RxHdrFifoCorErrLogC_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxHdrFifoCorErrLogC_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxDataFifoCorErrLogA_1_offset 0x00002968UL
struct QIB_7322_RxDataFifoCorErrLogA_1_pb {
	pseudo_bit_t RxDataFifoCorErrData_63_0[64];
};
struct QIB_7322_RxDataFifoCorErrLogA_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxDataFifoCorErrLogA_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxDataFifoCorErrLogB_1_offset 0x00002970UL
struct QIB_7322_RxDataFifoCorErrLogB_1_pb {
	pseudo_bit_t RxDataFifoCorErrData_127_64[64];
};
struct QIB_7322_RxDataFifoCorErrLogB_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxDataFifoCorErrLogB_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxDataFifoCorErrLogC_1_offset 0x00002978UL
struct QIB_7322_RxDataFifoCorErrLogC_1_pb {
	pseudo_bit_t RxDataFifoCorErrCheckBit_15_0[16];
	pseudo_bit_t RxDataFifoCorErrAddr_10_0[11];
	pseudo_bit_t _unused_0[37];
};
struct QIB_7322_RxDataFifoCorErrLogC_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RxDataFifoCorErrLogC_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_LaFifoArray0CorErrLog_1_offset 0x00002980UL
struct QIB_7322_LaFifoArray0CorErrLog_1_pb {
	pseudo_bit_t LaFifoArray0CorErrData_34_0[35];
	pseudo_bit_t LaFifoArray0CorErrCheckBit_10_0[11];
	pseudo_bit_t LaFifoArray0CorErrAddr_10_0[11];
	pseudo_bit_t _unused_0[7];
};
struct QIB_7322_LaFifoArray0CorErrLog_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_LaFifoArray0CorErrLog_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RmFifoArrayCorErrLogA_1_offset 0x000029c0UL
struct QIB_7322_RmFifoArrayCorErrLogA_1_pb {
	pseudo_bit_t RmFifoArrayCorErrData_63_0[64];
};
struct QIB_7322_RmFifoArrayCorErrLogA_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RmFifoArrayCorErrLogA_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RmFifoArrayCorErrLogB_1_offset 0x000029c8UL
struct QIB_7322_RmFifoArrayCorErrLogB_1_pb {
	pseudo_bit_t RmFifoArrayCorErrData_127_64[64];
};
struct QIB_7322_RmFifoArrayCorErrLogB_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RmFifoArrayCorErrLogB_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RmFifoArrayCorErrLogC_1_offset 0x000029d0UL
struct QIB_7322_RmFifoArrayCorErrLogC_1_pb {
	pseudo_bit_t RmFifoArrayCorErrCheckBit_27_0[28];
	pseudo_bit_t RmFifoArrayCorErrAddr_13_0[14];
	pseudo_bit_t _unused_0[18];
	pseudo_bit_t RmFifoArrayCorErrDword_3_0[4];
};
struct QIB_7322_RmFifoArrayCorErrLogC_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RmFifoArrayCorErrLogC_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_HighPriorityLimit_1_offset 0x00002bc0UL
struct QIB_7322_HighPriorityLimit_1_pb {
	pseudo_bit_t Limit[8];
	pseudo_bit_t _unused_0[56];
};
struct QIB_7322_HighPriorityLimit_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_HighPriorityLimit_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_LowPriority0_1_offset 0x00002c00UL
struct QIB_7322_LowPriority0_1_pb {
	pseudo_bit_t Weight[8];
	pseudo_bit_t _unused_0[8];
	pseudo_bit_t VirtualLane[3];
	pseudo_bit_t _unused_1[45];
};
struct QIB_7322_LowPriority0_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_LowPriority0_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_HighPriority0_1_offset 0x00002e00UL
struct QIB_7322_HighPriority0_1_pb {
	pseudo_bit_t Weight[8];
	pseudo_bit_t _unused_0[8];
	pseudo_bit_t VirtualLane[3];
	pseudo_bit_t _unused_1[45];
};
struct QIB_7322_HighPriority0_1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_HighPriority0_1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufAvail0_offset 0x00003000UL
struct QIB_7322_SendBufAvail0_pb {
	pseudo_bit_t SendBuf_31_0[64];
};
struct QIB_7322_SendBufAvail0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SendBufAvail0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_MsixTable_offset 0x00008000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_MsixPba_offset 0x00009000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_LAMemory_offset 0x0000a000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_LBIntCnt_offset 0x00011000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_LBFlowStallCnt_offset 0x00011008UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxTIDFullErrCnt_offset 0x000110d0UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxTIDValidErrCnt_offset 0x000110d8UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxP0HdrEgrOvflCnt_offset 0x000110e8UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_PcieRetryBufDiagQwordCnt_offset 0x000111a0UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxTidFlowDropCnt_offset 0x000111e0UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_LBIntCnt_0_offset 0x00012000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_TxCreditUpToDateTimeOut_0_offset 0x00012008UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_TxSDmaDescCnt_0_offset 0x00012010UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_TxUnsupVLErrCnt_0_offset 0x00012018UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_TxDataPktCnt_0_offset 0x00012020UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_TxFlowPktCnt_0_offset 0x00012028UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_TxDwordCnt_0_offset 0x00012030UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_TxLenErrCnt_0_offset 0x00012038UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_TxMaxMinLenErrCnt_0_offset 0x00012040UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_TxUnderrunCnt_0_offset 0x00012048UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_TxFlowStallCnt_0_offset 0x00012050UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_TxDroppedPktCnt_0_offset 0x00012058UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxDroppedPktCnt_0_offset 0x00012060UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxDataPktCnt_0_offset 0x00012068UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxFlowPktCnt_0_offset 0x00012070UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxDwordCnt_0_offset 0x00012078UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxLenErrCnt_0_offset 0x00012080UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxMaxMinLenErrCnt_0_offset 0x00012088UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxICRCErrCnt_0_offset 0x00012090UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxVCRCErrCnt_0_offset 0x00012098UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxFlowCtrlViolCnt_0_offset 0x000120a0UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxVersionErrCnt_0_offset 0x000120a8UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxLinkMalformCnt_0_offset 0x000120b0UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxEBPCnt_0_offset 0x000120b8UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxLPCRCErrCnt_0_offset 0x000120c0UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxBufOvflCnt_0_offset 0x000120c8UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxLenTruncateCnt_0_offset 0x000120d0UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxPKeyMismatchCnt_0_offset 0x000120e0UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_IBLinkDownedCnt_0_offset 0x00012180UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_IBSymbolErrCnt_0_offset 0x00012188UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_IBStatusChangeCnt_0_offset 0x00012190UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_IBLinkErrRecoveryCnt_0_offset 0x00012198UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_ExcessBufferOvflCnt_0_offset 0x000121a8UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_LocalLinkIntegrityErrCnt_0_offset 0x000121b0UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxVlErrCnt_0_offset 0x000121b8UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxDlidFltrCnt_0_offset 0x000121c0UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxVL15DroppedPktCnt_0_offset 0x000121c8UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxOtherLocalPhyErrCnt_0_offset 0x000121d0UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxQPInvalidContextCnt_0_offset 0x000121d8UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_TxHeadersErrCnt_0_offset 0x000121f8UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_PSRcvDataCount_0_offset 0x00012218UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_PSRcvPktsCount_0_offset 0x00012220UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_PSXmitDataCount_0_offset 0x00012228UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_PSXmitPktsCount_0_offset 0x00012230UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_PSXmitWaitCount_0_offset 0x00012238UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_LBIntCnt_1_offset 0x00013000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_TxCreditUpToDateTimeOut_1_offset 0x00013008UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_TxSDmaDescCnt_1_offset 0x00013010UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_TxUnsupVLErrCnt_1_offset 0x00013018UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_TxDataPktCnt_1_offset 0x00013020UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_TxFlowPktCnt_1_offset 0x00013028UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_TxDwordCnt_1_offset 0x00013030UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_TxLenErrCnt_1_offset 0x00013038UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_TxMaxMinLenErrCnt_1_offset 0x00013040UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_TxUnderrunCnt_1_offset 0x00013048UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_TxFlowStallCnt_1_offset 0x00013050UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_TxDroppedPktCnt_1_offset 0x00013058UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxDroppedPktCnt_1_offset 0x00013060UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxDataPktCnt_1_offset 0x00013068UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxFlowPktCnt_1_offset 0x00013070UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxDwordCnt_1_offset 0x00013078UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxLenErrCnt_1_offset 0x00013080UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxMaxMinLenErrCnt_1_offset 0x00013088UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxICRCErrCnt_1_offset 0x00013090UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxVCRCErrCnt_1_offset 0x00013098UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxFlowCtrlViolCnt_1_offset 0x000130a0UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxVersionErrCnt_1_offset 0x000130a8UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxLinkMalformCnt_1_offset 0x000130b0UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxEBPCnt_1_offset 0x000130b8UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxLPCRCErrCnt_1_offset 0x000130c0UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxBufOvflCnt_1_offset 0x000130c8UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxLenTruncateCnt_1_offset 0x000130d0UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxPKeyMismatchCnt_1_offset 0x000130e0UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_IBLinkDownedCnt_1_offset 0x00013180UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_IBSymbolErrCnt_1_offset 0x00013188UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_IBStatusChangeCnt_1_offset 0x00013190UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_IBLinkErrRecoveryCnt_1_offset 0x00013198UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_ExcessBufferOvflCnt_1_offset 0x000131a8UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_LocalLinkIntegrityErrCnt_1_offset 0x000131b0UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxVlErrCnt_1_offset 0x000131b8UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxDlidFltrCnt_1_offset 0x000131c0UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxVL15DroppedPktCnt_1_offset 0x000131c8UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxOtherLocalPhyErrCnt_1_offset 0x000131d0UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RxQPInvalidContextCnt_1_offset 0x000131d8UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_TxHeadersErrCnt_1_offset 0x000131f8UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_PSRcvDataCount_1_offset 0x00013218UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_PSRcvPktsCount_1_offset 0x00013220UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_PSXmitDataCount_1_offset 0x00013228UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_PSXmitPktsCount_1_offset 0x00013230UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_PSXmitWaitCount_1_offset 0x00013238UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvEgrArray_offset 0x00014000UL
struct QIB_7322_RcvEgrArray_pb {
	pseudo_bit_t RT_Addr[37];
	pseudo_bit_t RT_BufSize[3];
	pseudo_bit_t _unused_0[24];
};
struct QIB_7322_RcvEgrArray {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvEgrArray_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvTIDArray0_offset 0x00050000UL
struct QIB_7322_RcvTIDArray0_pb {
	pseudo_bit_t RT_Addr[37];
	pseudo_bit_t RT_BufSize[3];
	pseudo_bit_t _unused_0[24];
};
struct QIB_7322_RcvTIDArray0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvTIDArray0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendPbcCache_offset 0x00070000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_LaunchFIFO_v0p0_offset 0x00072000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_LaunchElement_v15p0_offset 0x00076000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_PreLaunchFIFO_0_offset 0x00076100UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_ScoreBoard_0_offset 0x00076200UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_DescriptorFIFO_0_offset 0x00076300UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_LaunchFIFO_v0p1_offset 0x00078000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_LaunchElement_v15p1_offset 0x0007c000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_PreLaunchFIFO_1_offset 0x0007c100UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_ScoreBoard_1_offset 0x0007c200UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_DescriptorFIFO_1_offset 0x0007c300UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvBufA_0_offset 0x00080000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvBufB_0_offset 0x00088000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvFlags_0_offset 0x0008a000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvLookupiqBuf_0_offset 0x0008c000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvDMADatBuf_0_offset 0x0008e000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvDMAHdrBuf_0_offset 0x0008e800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvBufA_1_offset 0x00090000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvBufB_1_offset 0x00098000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvFlags_1_offset 0x0009a000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvLookupiqBuf_1_offset 0x0009c000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvDMADatBuf_1_offset 0x0009e000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvDMAHdrBuf_1_offset 0x0009e800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_PCIERcvBuf_offset 0x000a0000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_PCIERetryBuf_offset 0x000a4000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_PCIERcvBufRdToWrAddr_offset 0x000a8000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_PCIERcvHdrRdToWrAddr_offset 0x000b0000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_PCIECplBuf_offset 0x000b8000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_PCIECplHdr_offset 0x000bc000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_PCIERcvHdr_offset 0x000bc200UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_IBSD_DDS_MAP_TABLE_0_offset 0x000d0000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_0_offset 0x00100000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_0_offset 0x00100800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_1_offset 0x00101000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_1_offset 0x00101800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_2_offset 0x00102000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_2_offset 0x00102800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_3_offset 0x00103000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_3_offset 0x00103800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_4_offset 0x00104000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_4_offset 0x00104800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_5_offset 0x00105000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_5_offset 0x00105800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_6_offset 0x00106000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_6_offset 0x00106800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_7_offset 0x00107000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_7_offset 0x00107800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_8_offset 0x00108000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_8_offset 0x00108800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_9_offset 0x00109000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_9_offset 0x00109800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_10_offset 0x0010a000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_10_offset 0x0010a800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_11_offset 0x0010b000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_11_offset 0x0010b800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_12_offset 0x0010c000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_12_offset 0x0010c800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_13_offset 0x0010d000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_13_offset 0x0010d800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_14_offset 0x0010e000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_14_offset 0x0010e800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_15_offset 0x0010f000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_15_offset 0x0010f800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_16_offset 0x00110000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_16_offset 0x00110800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_17_offset 0x00111000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_17_offset 0x00111800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_18_offset 0x00112000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_18_offset 0x00112800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_19_offset 0x00113000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_19_offset 0x00113800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_20_offset 0x00114000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_20_offset 0x00114800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_21_offset 0x00115000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_21_offset 0x00115800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_22_offset 0x00116000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_22_offset 0x00116800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_23_offset 0x00117000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_23_offset 0x00117800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_24_offset 0x00118000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_24_offset 0x00118800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_25_offset 0x00119000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_25_offset 0x00119800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_26_offset 0x0011a000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_26_offset 0x0011a800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_27_offset 0x0011b000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_27_offset 0x0011b800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_28_offset 0x0011c000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_28_offset 0x0011c800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_29_offset 0x0011d000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_29_offset 0x0011d800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_30_offset 0x0011e000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_30_offset 0x0011e800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_31_offset 0x0011f000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_31_offset 0x0011f800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_32_offset 0x00120000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_32_offset 0x00120800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_33_offset 0x00121000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_33_offset 0x00121800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_34_offset 0x00122000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_34_offset 0x00122800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_35_offset 0x00123000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_35_offset 0x00123800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_36_offset 0x00124000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_36_offset 0x00124800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_37_offset 0x00125000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_37_offset 0x00125800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_38_offset 0x00126000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_38_offset 0x00126800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_39_offset 0x00127000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_39_offset 0x00127800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_40_offset 0x00128000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_40_offset 0x00128800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_41_offset 0x00129000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_41_offset 0x00129800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_42_offset 0x0012a000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_42_offset 0x0012a800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_43_offset 0x0012b000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_43_offset 0x0012b800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_44_offset 0x0012c000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_44_offset 0x0012c800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_45_offset 0x0012d000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_45_offset 0x0012d800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_46_offset 0x0012e000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_46_offset 0x0012e800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_47_offset 0x0012f000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_47_offset 0x0012f800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_48_offset 0x00130000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_48_offset 0x00130800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_49_offset 0x00131000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_49_offset 0x00131800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_50_offset 0x00132000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_50_offset 0x00132800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_51_offset 0x00133000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_51_offset 0x00133800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_52_offset 0x00134000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_52_offset 0x00134800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_53_offset 0x00135000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_53_offset 0x00135800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_54_offset 0x00136000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_54_offset 0x00136800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_55_offset 0x00137000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_55_offset 0x00137800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_56_offset 0x00138000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_56_offset 0x00138800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_57_offset 0x00139000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_57_offset 0x00139800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_58_offset 0x0013a000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_58_offset 0x0013a800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_59_offset 0x0013b000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_59_offset 0x0013b800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_60_offset 0x0013c000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_60_offset 0x0013c800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_61_offset 0x0013d000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_61_offset 0x0013d800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_62_offset 0x0013e000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_62_offset 0x0013e800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_63_offset 0x0013f000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_63_offset 0x0013f800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_64_offset 0x00140000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_64_offset 0x00140800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_65_offset 0x00141000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_65_offset 0x00141800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_66_offset 0x00142000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_66_offset 0x00142800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_67_offset 0x00143000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_67_offset 0x00143800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_68_offset 0x00144000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_68_offset 0x00144800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_69_offset 0x00145000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_69_offset 0x00145800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_70_offset 0x00146000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_70_offset 0x00146800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_71_offset 0x00147000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_71_offset 0x00147800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_72_offset 0x00148000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_72_offset 0x00148800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_73_offset 0x00149000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_73_offset 0x00149800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_74_offset 0x0014a000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_74_offset 0x0014a800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_75_offset 0x0014b000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_75_offset 0x0014b800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_76_offset 0x0014c000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_76_offset 0x0014c800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_77_offset 0x0014d000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_77_offset 0x0014d800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_78_offset 0x0014e000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_78_offset 0x0014e800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_79_offset 0x0014f000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_79_offset 0x0014f800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_80_offset 0x00150000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_80_offset 0x00150800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_81_offset 0x00151000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_81_offset 0x00151800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_82_offset 0x00152000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_82_offset 0x00152800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_83_offset 0x00153000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_83_offset 0x00153800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_84_offset 0x00154000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_84_offset 0x00154800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_85_offset 0x00155000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_85_offset 0x00155800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_86_offset 0x00156000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_86_offset 0x00156800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_87_offset 0x00157000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_87_offset 0x00157800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_88_offset 0x00158000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_88_offset 0x00158800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_89_offset 0x00159000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_89_offset 0x00159800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_90_offset 0x0015a000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_90_offset 0x0015a800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_91_offset 0x0015b000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_91_offset 0x0015b800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_92_offset 0x0015c000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_92_offset 0x0015c800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_93_offset 0x0015d000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_93_offset 0x0015d800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_94_offset 0x0015e000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_94_offset 0x0015e800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_95_offset 0x0015f000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_95_offset 0x0015f800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_96_offset 0x00160000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_96_offset 0x00160800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_97_offset 0x00161000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_97_offset 0x00161800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_98_offset 0x00162000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_98_offset 0x00162800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_99_offset 0x00163000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_99_offset 0x00163800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_100_offset 0x00164000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_100_offset 0x00164800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_101_offset 0x00165000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_101_offset 0x00165800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_102_offset 0x00166000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_102_offset 0x00166800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_103_offset 0x00167000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_103_offset 0x00167800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_104_offset 0x00168000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_104_offset 0x00168800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_105_offset 0x00169000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_105_offset 0x00169800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_106_offset 0x0016a000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_106_offset 0x0016a800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_107_offset 0x0016b000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_107_offset 0x0016b800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_108_offset 0x0016c000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_108_offset 0x0016c800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_109_offset 0x0016d000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_109_offset 0x0016d800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_110_offset 0x0016e000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_110_offset 0x0016e800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_111_offset 0x0016f000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_111_offset 0x0016f800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_112_offset 0x00170000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_112_offset 0x00170800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_113_offset 0x00171000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_113_offset 0x00171800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_114_offset 0x00172000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_114_offset 0x00172800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_115_offset 0x00173000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_115_offset 0x00173800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_116_offset 0x00174000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_116_offset 0x00174800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_117_offset 0x00175000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_117_offset 0x00175800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_118_offset 0x00176000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_118_offset 0x00176800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_119_offset 0x00177000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_119_offset 0x00177800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_120_offset 0x00178000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_120_offset 0x00178800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_121_offset 0x00179000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_121_offset 0x00179800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_122_offset 0x0017a000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_122_offset 0x0017a800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_123_offset 0x0017b000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_123_offset 0x0017b800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_124_offset 0x0017c000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_124_offset 0x0017c800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_125_offset 0x0017d000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_125_offset 0x0017d800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_126_offset 0x0017e000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_126_offset 0x0017e800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_127_offset 0x0017f000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_127_offset 0x0017f800UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_128_offset 0x00180000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_128_offset 0x00181000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_129_offset 0x00182000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_129_offset 0x00183000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_130_offset 0x00184000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_130_offset 0x00185000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_131_offset 0x00186000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_131_offset 0x00187000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_132_offset 0x00188000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_132_offset 0x00189000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_133_offset 0x0018a000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_133_offset 0x0018b000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_134_offset 0x0018c000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_134_offset 0x0018d000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_135_offset 0x0018e000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_135_offset 0x0018f000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_136_offset 0x00190000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_136_offset 0x00191000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_137_offset 0x00192000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_137_offset 0x00193000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_138_offset 0x00194000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_138_offset 0x00195000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_139_offset 0x00196000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_139_offset 0x00197000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_140_offset 0x00198000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_140_offset 0x00199000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_141_offset 0x0019a000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_141_offset 0x0019b000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_142_offset 0x0019c000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_142_offset 0x0019d000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_143_offset 0x0019e000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_143_offset 0x0019f000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_144_offset 0x001a0000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_144_offset 0x001a1000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_145_offset 0x001a2000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_145_offset 0x001a3000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_146_offset 0x001a4000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_146_offset 0x001a5000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_147_offset 0x001a6000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_147_offset 0x001a7000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_148_offset 0x001a8000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_148_offset 0x001a9000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_149_offset 0x001aa000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_149_offset 0x001ab000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_150_offset 0x001ac000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_150_offset 0x001ad000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_151_offset 0x001ae000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_151_offset 0x001af000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_152_offset 0x001b0000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_152_offset 0x001b1000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_153_offset 0x001b2000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_153_offset 0x001b3000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_154_offset 0x001b4000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_154_offset 0x001b5000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_155_offset 0x001b6000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_155_offset 0x001b7000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_156_offset 0x001b8000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_156_offset 0x001b9000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_157_offset 0x001ba000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_157_offset 0x001bb000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_158_offset 0x001bc000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_158_offset 0x001bd000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufMA_159_offset 0x001be000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufEA_159_offset 0x001bf000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_SendBufVL15_0_offset 0x001c0000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvHdrTail0_offset 0x00200000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvHdrHead0_offset 0x00200008UL
struct QIB_7322_RcvHdrHead0_pb {
	pseudo_bit_t RcvHeadPointer[32];
	pseudo_bit_t counter[16];
	pseudo_bit_t _unused_0[16];
};
struct QIB_7322_RcvHdrHead0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvHdrHead0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvEgrIndexTail0_offset 0x00200010UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvEgrIndexHead0_offset 0x00200018UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvTIDFlowTable0_offset 0x00201000UL
struct QIB_7322_RcvTIDFlowTable0_pb {
	pseudo_bit_t SeqNum[11];
	pseudo_bit_t GenVal[8];
	pseudo_bit_t FlowValid[1];
	pseudo_bit_t HdrSuppEnabled[1];
	pseudo_bit_t KeepAfterSeqErr[1];
	pseudo_bit_t KeepOnGenErr[1];
	pseudo_bit_t _unused_0[4];
	pseudo_bit_t SeqMismatch[1];
	pseudo_bit_t GenMismatch[1];
	pseudo_bit_t _unused_1[35];
};
struct QIB_7322_RcvTIDFlowTable0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvTIDFlowTable0_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvHdrTail1_offset 0x00210000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvHdrHead1_offset 0x00210008UL
struct QIB_7322_RcvHdrHead1_pb {
	pseudo_bit_t RcvHeadPointer[32];
	pseudo_bit_t counter[16];
	pseudo_bit_t _unused_0[16];
};
struct QIB_7322_RcvHdrHead1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvHdrHead1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvEgrIndexTail1_offset 0x00210010UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvEgrIndexHead1_offset 0x00210018UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvTIDFlowTable1_offset 0x00211000UL
struct QIB_7322_RcvTIDFlowTable1_pb {
	pseudo_bit_t SeqNum[11];
	pseudo_bit_t GenVal[8];
	pseudo_bit_t FlowValid[1];
	pseudo_bit_t HdrSuppEnabled[1];
	pseudo_bit_t KeepAfterSeqErr[1];
	pseudo_bit_t KeepOnGenErr[1];
	pseudo_bit_t _unused_0[4];
	pseudo_bit_t SeqMismatch[1];
	pseudo_bit_t GenMismatch[1];
	pseudo_bit_t _unused_1[35];
};
struct QIB_7322_RcvTIDFlowTable1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvTIDFlowTable1_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvHdrTail2_offset 0x00220000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvHdrHead2_offset 0x00220008UL
struct QIB_7322_RcvHdrHead2_pb {
	pseudo_bit_t RcvHeadPointer[32];
	pseudo_bit_t counter[16];
	pseudo_bit_t _unused_0[16];
};
struct QIB_7322_RcvHdrHead2 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvHdrHead2_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvEgrIndexTail2_offset 0x00220010UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvEgrIndexHead2_offset 0x00220018UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvTIDFlowTable2_offset 0x00221000UL
struct QIB_7322_RcvTIDFlowTable2_pb {
	pseudo_bit_t SeqNum[11];
	pseudo_bit_t GenVal[8];
	pseudo_bit_t FlowValid[1];
	pseudo_bit_t HdrSuppEnabled[1];
	pseudo_bit_t KeepAfterSeqErr[1];
	pseudo_bit_t KeepOnGenErr[1];
	pseudo_bit_t _unused_0[4];
	pseudo_bit_t SeqMismatch[1];
	pseudo_bit_t GenMismatch[1];
	pseudo_bit_t _unused_1[35];
};
struct QIB_7322_RcvTIDFlowTable2 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvTIDFlowTable2_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvHdrTail3_offset 0x00230000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvHdrHead3_offset 0x00230008UL
struct QIB_7322_RcvHdrHead3_pb {
	pseudo_bit_t RcvHeadPointer[32];
	pseudo_bit_t counter[16];
	pseudo_bit_t _unused_0[16];
};
struct QIB_7322_RcvHdrHead3 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvHdrHead3_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvEgrIndexTail3_offset 0x00230010UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvEgrIndexHead3_offset 0x00230018UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvTIDFlowTable3_offset 0x00231000UL
struct QIB_7322_RcvTIDFlowTable3_pb {
	pseudo_bit_t SeqNum[11];
	pseudo_bit_t GenVal[8];
	pseudo_bit_t FlowValid[1];
	pseudo_bit_t HdrSuppEnabled[1];
	pseudo_bit_t KeepAfterSeqErr[1];
	pseudo_bit_t KeepOnGenErr[1];
	pseudo_bit_t _unused_0[4];
	pseudo_bit_t SeqMismatch[1];
	pseudo_bit_t GenMismatch[1];
	pseudo_bit_t _unused_1[35];
};
struct QIB_7322_RcvTIDFlowTable3 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvTIDFlowTable3_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvHdrTail4_offset 0x00240000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvHdrHead4_offset 0x00240008UL
struct QIB_7322_RcvHdrHead4_pb {
	pseudo_bit_t RcvHeadPointer[32];
	pseudo_bit_t counter[16];
	pseudo_bit_t _unused_0[16];
};
struct QIB_7322_RcvHdrHead4 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvHdrHead4_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvEgrIndexTail4_offset 0x00240010UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvEgrIndexHead4_offset 0x00240018UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvTIDFlowTable4_offset 0x00241000UL
struct QIB_7322_RcvTIDFlowTable4_pb {
	pseudo_bit_t SeqNum[11];
	pseudo_bit_t GenVal[8];
	pseudo_bit_t FlowValid[1];
	pseudo_bit_t HdrSuppEnabled[1];
	pseudo_bit_t KeepAfterSeqErr[1];
	pseudo_bit_t KeepOnGenErr[1];
	pseudo_bit_t _unused_0[4];
	pseudo_bit_t SeqMismatch[1];
	pseudo_bit_t GenMismatch[1];
	pseudo_bit_t _unused_1[35];
};
struct QIB_7322_RcvTIDFlowTable4 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvTIDFlowTable4_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvHdrTail5_offset 0x00250000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvHdrHead5_offset 0x00250008UL
struct QIB_7322_RcvHdrHead5_pb {
	pseudo_bit_t RcvHeadPointer[32];
	pseudo_bit_t counter[16];
	pseudo_bit_t _unused_0[16];
};
struct QIB_7322_RcvHdrHead5 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvHdrHead5_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvEgrIndexTail5_offset 0x00250010UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvEgrIndexHead5_offset 0x00250018UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvTIDFlowTable5_offset 0x00251000UL
struct QIB_7322_RcvTIDFlowTable5_pb {
	pseudo_bit_t SeqNum[11];
	pseudo_bit_t GenVal[8];
	pseudo_bit_t FlowValid[1];
	pseudo_bit_t HdrSuppEnabled[1];
	pseudo_bit_t KeepAfterSeqErr[1];
	pseudo_bit_t KeepOnGenErr[1];
	pseudo_bit_t _unused_0[4];
	pseudo_bit_t SeqMismatch[1];
	pseudo_bit_t GenMismatch[1];
	pseudo_bit_t _unused_1[35];
};
struct QIB_7322_RcvTIDFlowTable5 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvTIDFlowTable5_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvHdrTail6_offset 0x00260000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvHdrHead6_offset 0x00260008UL
struct QIB_7322_RcvHdrHead6_pb {
	pseudo_bit_t RcvHeadPointer[32];
	pseudo_bit_t counter[16];
	pseudo_bit_t _unused_0[16];
};
struct QIB_7322_RcvHdrHead6 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvHdrHead6_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvEgrIndexTail6_offset 0x00260010UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvEgrIndexHead6_offset 0x00260018UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvTIDFlowTable6_offset 0x00261000UL
struct QIB_7322_RcvTIDFlowTable6_pb {
	pseudo_bit_t SeqNum[11];
	pseudo_bit_t GenVal[8];
	pseudo_bit_t FlowValid[1];
	pseudo_bit_t HdrSuppEnabled[1];
	pseudo_bit_t KeepAfterSeqErr[1];
	pseudo_bit_t KeepOnGenErr[1];
	pseudo_bit_t _unused_0[4];
	pseudo_bit_t SeqMismatch[1];
	pseudo_bit_t GenMismatch[1];
	pseudo_bit_t _unused_1[35];
};
struct QIB_7322_RcvTIDFlowTable6 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvTIDFlowTable6_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvHdrTail7_offset 0x00270000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvHdrHead7_offset 0x00270008UL
struct QIB_7322_RcvHdrHead7_pb {
	pseudo_bit_t RcvHeadPointer[32];
	pseudo_bit_t counter[16];
	pseudo_bit_t _unused_0[16];
};
struct QIB_7322_RcvHdrHead7 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvHdrHead7_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvEgrIndexTail7_offset 0x00270010UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvEgrIndexHead7_offset 0x00270018UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvTIDFlowTable7_offset 0x00271000UL
struct QIB_7322_RcvTIDFlowTable7_pb {
	pseudo_bit_t SeqNum[11];
	pseudo_bit_t GenVal[8];
	pseudo_bit_t FlowValid[1];
	pseudo_bit_t HdrSuppEnabled[1];
	pseudo_bit_t KeepAfterSeqErr[1];
	pseudo_bit_t KeepOnGenErr[1];
	pseudo_bit_t _unused_0[4];
	pseudo_bit_t SeqMismatch[1];
	pseudo_bit_t GenMismatch[1];
	pseudo_bit_t _unused_1[35];
};
struct QIB_7322_RcvTIDFlowTable7 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvTIDFlowTable7_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvHdrTail8_offset 0x00280000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvHdrHead8_offset 0x00280008UL
struct QIB_7322_RcvHdrHead8_pb {
	pseudo_bit_t RcvHeadPointer[32];
	pseudo_bit_t counter[16];
	pseudo_bit_t _unused_0[16];
};
struct QIB_7322_RcvHdrHead8 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvHdrHead8_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvEgrIndexTail8_offset 0x00280010UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvEgrIndexHead8_offset 0x00280018UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvTIDFlowTable8_offset 0x00281000UL
struct QIB_7322_RcvTIDFlowTable8_pb {
	pseudo_bit_t SeqNum[11];
	pseudo_bit_t GenVal[8];
	pseudo_bit_t FlowValid[1];
	pseudo_bit_t HdrSuppEnabled[1];
	pseudo_bit_t KeepAfterSeqErr[1];
	pseudo_bit_t KeepOnGenErr[1];
	pseudo_bit_t _unused_0[4];
	pseudo_bit_t SeqMismatch[1];
	pseudo_bit_t GenMismatch[1];
	pseudo_bit_t _unused_1[35];
};
struct QIB_7322_RcvTIDFlowTable8 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvTIDFlowTable8_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvHdrTail9_offset 0x00290000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvHdrHead9_offset 0x00290008UL
struct QIB_7322_RcvHdrHead9_pb {
	pseudo_bit_t RcvHeadPointer[32];
	pseudo_bit_t counter[16];
	pseudo_bit_t _unused_0[16];
};
struct QIB_7322_RcvHdrHead9 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvHdrHead9_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvEgrIndexTail9_offset 0x00290010UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvEgrIndexHead9_offset 0x00290018UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvTIDFlowTable9_offset 0x00291000UL
struct QIB_7322_RcvTIDFlowTable9_pb {
	pseudo_bit_t SeqNum[11];
	pseudo_bit_t GenVal[8];
	pseudo_bit_t FlowValid[1];
	pseudo_bit_t HdrSuppEnabled[1];
	pseudo_bit_t KeepAfterSeqErr[1];
	pseudo_bit_t KeepOnGenErr[1];
	pseudo_bit_t _unused_0[4];
	pseudo_bit_t SeqMismatch[1];
	pseudo_bit_t GenMismatch[1];
	pseudo_bit_t _unused_1[35];
};
struct QIB_7322_RcvTIDFlowTable9 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvTIDFlowTable9_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvHdrTail10_offset 0x002a0000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvHdrHead10_offset 0x002a0008UL
struct QIB_7322_RcvHdrHead10_pb {
	pseudo_bit_t RcvHeadPointer[32];
	pseudo_bit_t counter[16];
	pseudo_bit_t _unused_0[16];
};
struct QIB_7322_RcvHdrHead10 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvHdrHead10_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvEgrIndexTail10_offset 0x002a0010UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvEgrIndexHead10_offset 0x002a0018UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvTIDFlowTable10_offset 0x002a1000UL
struct QIB_7322_RcvTIDFlowTable10_pb {
	pseudo_bit_t SeqNum[11];
	pseudo_bit_t GenVal[8];
	pseudo_bit_t FlowValid[1];
	pseudo_bit_t HdrSuppEnabled[1];
	pseudo_bit_t KeepAfterSeqErr[1];
	pseudo_bit_t KeepOnGenErr[1];
	pseudo_bit_t _unused_0[4];
	pseudo_bit_t SeqMismatch[1];
	pseudo_bit_t GenMismatch[1];
	pseudo_bit_t _unused_1[35];
};
struct QIB_7322_RcvTIDFlowTable10 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvTIDFlowTable10_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvHdrTail11_offset 0x002b0000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvHdrHead11_offset 0x002b0008UL
struct QIB_7322_RcvHdrHead11_pb {
	pseudo_bit_t RcvHeadPointer[32];
	pseudo_bit_t counter[16];
	pseudo_bit_t _unused_0[16];
};
struct QIB_7322_RcvHdrHead11 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvHdrHead11_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvEgrIndexTail11_offset 0x002b0010UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvEgrIndexHead11_offset 0x002b0018UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvTIDFlowTable11_offset 0x002b1000UL
struct QIB_7322_RcvTIDFlowTable11_pb {
	pseudo_bit_t SeqNum[11];
	pseudo_bit_t GenVal[8];
	pseudo_bit_t FlowValid[1];
	pseudo_bit_t HdrSuppEnabled[1];
	pseudo_bit_t KeepAfterSeqErr[1];
	pseudo_bit_t KeepOnGenErr[1];
	pseudo_bit_t _unused_0[4];
	pseudo_bit_t SeqMismatch[1];
	pseudo_bit_t GenMismatch[1];
	pseudo_bit_t _unused_1[35];
};
struct QIB_7322_RcvTIDFlowTable11 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvTIDFlowTable11_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvHdrTail12_offset 0x002c0000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvHdrHead12_offset 0x002c0008UL
struct QIB_7322_RcvHdrHead12_pb {
	pseudo_bit_t RcvHeadPointer[32];
	pseudo_bit_t counter[16];
	pseudo_bit_t _unused_0[16];
};
struct QIB_7322_RcvHdrHead12 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvHdrHead12_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvEgrIndexTail12_offset 0x002c0010UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvEgrIndexHead12_offset 0x002c0018UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvTIDFlowTable12_offset 0x002c1000UL
struct QIB_7322_RcvTIDFlowTable12_pb {
	pseudo_bit_t SeqNum[11];
	pseudo_bit_t GenVal[8];
	pseudo_bit_t FlowValid[1];
	pseudo_bit_t HdrSuppEnabled[1];
	pseudo_bit_t KeepAfterSeqErr[1];
	pseudo_bit_t KeepOnGenErr[1];
	pseudo_bit_t _unused_0[4];
	pseudo_bit_t SeqMismatch[1];
	pseudo_bit_t GenMismatch[1];
	pseudo_bit_t _unused_1[35];
};
struct QIB_7322_RcvTIDFlowTable12 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvTIDFlowTable12_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvHdrTail13_offset 0x002d0000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvHdrHead13_offset 0x002d0008UL
struct QIB_7322_RcvHdrHead13_pb {
	pseudo_bit_t RcvHeadPointer[32];
	pseudo_bit_t counter[16];
	pseudo_bit_t _unused_0[16];
};
struct QIB_7322_RcvHdrHead13 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvHdrHead13_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvEgrIndexTail13_offset 0x002d0010UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvEgrIndexHead13_offset 0x002d0018UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvTIDFlowTable13_offset 0x002d1000UL
struct QIB_7322_RcvTIDFlowTable13_pb {
	pseudo_bit_t SeqNum[11];
	pseudo_bit_t GenVal[8];
	pseudo_bit_t FlowValid[1];
	pseudo_bit_t HdrSuppEnabled[1];
	pseudo_bit_t KeepAfterSeqErr[1];
	pseudo_bit_t KeepOnGenErr[1];
	pseudo_bit_t _unused_0[4];
	pseudo_bit_t SeqMismatch[1];
	pseudo_bit_t GenMismatch[1];
	pseudo_bit_t _unused_1[35];
};
struct QIB_7322_RcvTIDFlowTable13 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvTIDFlowTable13_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvHdrTail14_offset 0x002e0000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvHdrHead14_offset 0x002e0008UL
struct QIB_7322_RcvHdrHead14_pb {
	pseudo_bit_t RcvHeadPointer[32];
	pseudo_bit_t counter[16];
	pseudo_bit_t _unused_0[16];
};
struct QIB_7322_RcvHdrHead14 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvHdrHead14_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvEgrIndexTail14_offset 0x002e0010UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvEgrIndexHead14_offset 0x002e0018UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvTIDFlowTable14_offset 0x002e1000UL
struct QIB_7322_RcvTIDFlowTable14_pb {
	pseudo_bit_t SeqNum[11];
	pseudo_bit_t GenVal[8];
	pseudo_bit_t FlowValid[1];
	pseudo_bit_t HdrSuppEnabled[1];
	pseudo_bit_t KeepAfterSeqErr[1];
	pseudo_bit_t KeepOnGenErr[1];
	pseudo_bit_t _unused_0[4];
	pseudo_bit_t SeqMismatch[1];
	pseudo_bit_t GenMismatch[1];
	pseudo_bit_t _unused_1[35];
};
struct QIB_7322_RcvTIDFlowTable14 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvTIDFlowTable14_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvHdrTail15_offset 0x002f0000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvHdrHead15_offset 0x002f0008UL
struct QIB_7322_RcvHdrHead15_pb {
	pseudo_bit_t RcvHeadPointer[32];
	pseudo_bit_t counter[16];
	pseudo_bit_t _unused_0[16];
};
struct QIB_7322_RcvHdrHead15 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvHdrHead15_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvEgrIndexTail15_offset 0x002f0010UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvEgrIndexHead15_offset 0x002f0018UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvTIDFlowTable15_offset 0x002f1000UL
struct QIB_7322_RcvTIDFlowTable15_pb {
	pseudo_bit_t SeqNum[11];
	pseudo_bit_t GenVal[8];
	pseudo_bit_t FlowValid[1];
	pseudo_bit_t HdrSuppEnabled[1];
	pseudo_bit_t KeepAfterSeqErr[1];
	pseudo_bit_t KeepOnGenErr[1];
	pseudo_bit_t _unused_0[4];
	pseudo_bit_t SeqMismatch[1];
	pseudo_bit_t GenMismatch[1];
	pseudo_bit_t _unused_1[35];
};
struct QIB_7322_RcvTIDFlowTable15 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvTIDFlowTable15_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvHdrTail16_offset 0x00300000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvHdrHead16_offset 0x00300008UL
struct QIB_7322_RcvHdrHead16_pb {
	pseudo_bit_t RcvHeadPointer[32];
	pseudo_bit_t counter[16];
	pseudo_bit_t _unused_0[16];
};
struct QIB_7322_RcvHdrHead16 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvHdrHead16_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvEgrIndexTail16_offset 0x00300010UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvEgrIndexHead16_offset 0x00300018UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvTIDFlowTable16_offset 0x00301000UL
struct QIB_7322_RcvTIDFlowTable16_pb {
	pseudo_bit_t SeqNum[11];
	pseudo_bit_t GenVal[8];
	pseudo_bit_t FlowValid[1];
	pseudo_bit_t HdrSuppEnabled[1];
	pseudo_bit_t KeepAfterSeqErr[1];
	pseudo_bit_t KeepOnGenErr[1];
	pseudo_bit_t _unused_0[4];
	pseudo_bit_t SeqMismatch[1];
	pseudo_bit_t GenMismatch[1];
	pseudo_bit_t _unused_1[35];
};
struct QIB_7322_RcvTIDFlowTable16 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvTIDFlowTable16_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvHdrTail17_offset 0x00310000UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvHdrHead17_offset 0x00310008UL
struct QIB_7322_RcvHdrHead17_pb {
	pseudo_bit_t RcvHeadPointer[32];
	pseudo_bit_t counter[16];
	pseudo_bit_t _unused_0[16];
};
struct QIB_7322_RcvHdrHead17 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvHdrHead17_pb );
};
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvEgrIndexTail17_offset 0x00310010UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvEgrIndexHead17_offset 0x00310018UL
/* Default value: 0x0000000000000000 */

#define QIB_7322_RcvTIDFlowTable17_offset 0x00311000UL
struct QIB_7322_RcvTIDFlowTable17_pb {
	pseudo_bit_t SeqNum[11];
	pseudo_bit_t GenVal[8];
	pseudo_bit_t FlowValid[1];
	pseudo_bit_t HdrSuppEnabled[1];
	pseudo_bit_t KeepAfterSeqErr[1];
	pseudo_bit_t KeepOnGenErr[1];
	pseudo_bit_t _unused_0[4];
	pseudo_bit_t SeqMismatch[1];
	pseudo_bit_t GenMismatch[1];
	pseudo_bit_t _unused_1[35];
};
struct QIB_7322_RcvTIDFlowTable17 {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvTIDFlowTable17_pb );
};
/* Default value: 0x0000000000000000 */

