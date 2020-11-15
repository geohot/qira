/*
 * Copyright (c) 2008, 2009 QLogic Corporation. All rights reserved.
 *
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
 *
 */
/* This file is mechanically generated from RTL. Any hand-edits will be lost! */

/* This file has been further processed by ./drivers/infiniband/qib_genbits.pl */

FILE_LICENCE ( GPL2_ONLY );

#define QIB_7220_Revision_offset 0x00000000UL
struct QIB_7220_Revision_pb {
	pseudo_bit_t R_ChipRevMinor[8];
	pseudo_bit_t R_ChipRevMajor[8];
	pseudo_bit_t R_Arch[8];
	pseudo_bit_t R_SW[8];
	pseudo_bit_t BoardID[8];
	pseudo_bit_t R_Emulation_Revcode[22];
	pseudo_bit_t R_Emulation[1];
	pseudo_bit_t R_Simulator[1];
};
struct QIB_7220_Revision {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_Revision_pb );
};

#define QIB_7220_Control_offset 0x00000008UL
struct QIB_7220_Control_pb {
	pseudo_bit_t SyncReset[1];
	pseudo_bit_t FreezeMode[1];
	pseudo_bit_t LinkEn[1];
	pseudo_bit_t PCIERetryBufDiagEn[1];
	pseudo_bit_t TxLatency[1];
	pseudo_bit_t Reserved[1];
	pseudo_bit_t PCIECplQDiagEn[1];
	pseudo_bit_t SyncResetExceptPcieIRAMRST[1];
	pseudo_bit_t _unused_0[56];
};
struct QIB_7220_Control {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_Control_pb );
};

#define QIB_7220_PageAlign_offset 0x00000010UL

#define QIB_7220_PortCnt_offset 0x00000018UL

#define QIB_7220_DbgPortSel_offset 0x00000020UL
struct QIB_7220_DbgPortSel_pb {
	pseudo_bit_t NibbleSel0[4];
	pseudo_bit_t NibbleSel1[4];
	pseudo_bit_t NibbleSel2[4];
	pseudo_bit_t NibbleSel3[4];
	pseudo_bit_t NibbleSel4[4];
	pseudo_bit_t NibbleSel5[4];
	pseudo_bit_t NibbleSel6[4];
	pseudo_bit_t NibbleSel7[4];
	pseudo_bit_t SrcMuxSel[14];
	pseudo_bit_t DbgClkPortSel[5];
	pseudo_bit_t EnDbgPort[1];
	pseudo_bit_t EnEnhancedDebugMode[1];
	pseudo_bit_t EnhMode_SrcMuxSelIndex[10];
	pseudo_bit_t EnhMode_SrcMuxSelWrEn[1];
};
struct QIB_7220_DbgPortSel {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_DbgPortSel_pb );
};

#define QIB_7220_DebugSigsIntSel_offset 0x00000028UL
struct QIB_7220_DebugSigsIntSel_pb {
	pseudo_bit_t debug_port_sel_pcs_pipe_lane07[3];
	pseudo_bit_t debug_port_sel_pcs_pipe_lane815[3];
	pseudo_bit_t debug_port_sel_pcs_sdout[1];
	pseudo_bit_t debug_port_sel_pcs_symlock_elfifo_lane[4];
	pseudo_bit_t debug_port_sel_pcs_rxdet_encdec_lane[4];
	pseudo_bit_t debug_port_sel_pcie_rx_tx[1];
	pseudo_bit_t debug_port_sel_xgxs[4];
	pseudo_bit_t debug_port_sel_epb_pcie[1];
	pseudo_bit_t _unused_0[43];
};
struct QIB_7220_DebugSigsIntSel {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_DebugSigsIntSel_pb );
};

#define QIB_7220_SendRegBase_offset 0x00000030UL

#define QIB_7220_UserRegBase_offset 0x00000038UL

#define QIB_7220_CntrRegBase_offset 0x00000040UL

#define QIB_7220_Scratch_offset 0x00000048UL

#define QIB_7220_REG_000050_offset 0x00000050UL

#define QIB_7220_IntBlocked_offset 0x00000060UL
struct QIB_7220_IntBlocked_pb {
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
	pseudo_bit_t Reserved1[9];
	pseudo_bit_t JIntBlocked[1];
	pseudo_bit_t IBSerdesTrimDoneIntBlocked[1];
	pseudo_bit_t assertGPIOIntBlocked[1];
	pseudo_bit_t PioBufAvailIntBlocked[1];
	pseudo_bit_t PioSetIntBlocked[1];
	pseudo_bit_t ErrorIntBlocked[1];
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
	pseudo_bit_t Reserved[13];
	pseudo_bit_t SDmaDisabledBlocked[1];
	pseudo_bit_t SDmaIntBlocked[1];
};
struct QIB_7220_IntBlocked {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_IntBlocked_pb );
};

#define QIB_7220_IntMask_offset 0x00000068UL
struct QIB_7220_IntMask_pb {
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
	pseudo_bit_t Reserved1[9];
	pseudo_bit_t JIntMask[1];
	pseudo_bit_t IBSerdesTrimDoneIntMask[1];
	pseudo_bit_t assertGPIOIntMask[1];
	pseudo_bit_t PioBufAvailIntMask[1];
	pseudo_bit_t PioSetIntMask[1];
	pseudo_bit_t ErrorIntMask[1];
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
	pseudo_bit_t Reserved[13];
	pseudo_bit_t SDmaDisabledMasked[1];
	pseudo_bit_t SDmaIntMask[1];
};
struct QIB_7220_IntMask {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_IntMask_pb );
};

#define QIB_7220_IntStatus_offset 0x00000070UL
struct QIB_7220_IntStatus_pb {
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
	pseudo_bit_t Reserved1[9];
	pseudo_bit_t JInt[1];
	pseudo_bit_t IBSerdesTrimDone[1];
	pseudo_bit_t assertGPIO[1];
	pseudo_bit_t PioBufAvail[1];
	pseudo_bit_t PioSent[1];
	pseudo_bit_t Error[1];
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
	pseudo_bit_t Reserved[13];
	pseudo_bit_t SDmaDisabled[1];
	pseudo_bit_t SDmaInt[1];
};
struct QIB_7220_IntStatus {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_IntStatus_pb );
};

#define QIB_7220_IntClear_offset 0x00000078UL
struct QIB_7220_IntClear_pb {
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
	pseudo_bit_t Reserved1[9];
	pseudo_bit_t JIntClear[1];
	pseudo_bit_t IBSerdesTrimDoneClear[1];
	pseudo_bit_t assertGPIOIntClear[1];
	pseudo_bit_t PioBufAvailIntClear[1];
	pseudo_bit_t PioSetIntClear[1];
	pseudo_bit_t ErrorIntClear[1];
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
	pseudo_bit_t Reserved[13];
	pseudo_bit_t SDmaDisabledClear[1];
	pseudo_bit_t SDmaIntClear[1];
};
struct QIB_7220_IntClear {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_IntClear_pb );
};

#define QIB_7220_ErrMask_offset 0x00000080UL
struct QIB_7220_ErrMask_pb {
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
	pseudo_bit_t RcvEgrFullErrMask[1];
	pseudo_bit_t RcvHdrFullErrMask[1];
	pseudo_bit_t RcvBadTidErrMask[1];
	pseudo_bit_t RcvHdrLenErrMask[1];
	pseudo_bit_t RcvHdrErrMask[1];
	pseudo_bit_t RcvIBLostLinkErrMask[1];
	pseudo_bit_t Reserved1[9];
	pseudo_bit_t SendSpecialTriggerErrMask[1];
	pseudo_bit_t SDmaDisabledErrMask[1];
	pseudo_bit_t SendMinPktLenErrMask[1];
	pseudo_bit_t SendMaxPktLenErrMask[1];
	pseudo_bit_t SendUnderRunErrMask[1];
	pseudo_bit_t SendPktLenErrMask[1];
	pseudo_bit_t SendDroppedSmpPktErrMask[1];
	pseudo_bit_t SendDroppedDataPktErrMask[1];
	pseudo_bit_t SendPioArmLaunchErrMask[1];
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
	pseudo_bit_t IBStatusChangedMask[1];
	pseudo_bit_t InvalidAddrErrMask[1];
	pseudo_bit_t ResetNegatedMask[1];
	pseudo_bit_t HardwareErrMask[1];
	pseudo_bit_t SDmaDescAddrMisalignErrMask[1];
	pseudo_bit_t InvalidEEPCmdMask[1];
	pseudo_bit_t Reserved[10];
};
struct QIB_7220_ErrMask {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_ErrMask_pb );
};

#define QIB_7220_ErrStatus_offset 0x00000088UL
struct QIB_7220_ErrStatus_pb {
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
	pseudo_bit_t RcvEgrFullErr[1];
	pseudo_bit_t RcvHdrFullErr[1];
	pseudo_bit_t RcvBadTidErr[1];
	pseudo_bit_t RcvHdrLenErr[1];
	pseudo_bit_t RcvHdrErr[1];
	pseudo_bit_t RcvIBLostLinkErr[1];
	pseudo_bit_t Reserved1[9];
	pseudo_bit_t SendSpecialTriggerErr[1];
	pseudo_bit_t SDmaDisabledErr[1];
	pseudo_bit_t SendMinPktLenErr[1];
	pseudo_bit_t SendMaxPktLenErr[1];
	pseudo_bit_t SendUnderRunErr[1];
	pseudo_bit_t SendPktLenErr[1];
	pseudo_bit_t SendDroppedSmpPktErr[1];
	pseudo_bit_t SendDroppedDataPktErr[1];
	pseudo_bit_t SendPioArmLaunchErr[1];
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
	pseudo_bit_t IBStatusChanged[1];
	pseudo_bit_t InvalidAddrErr[1];
	pseudo_bit_t ResetNegated[1];
	pseudo_bit_t HardwareErr[1];
	pseudo_bit_t SDmaDescAddrMisalignErr[1];
	pseudo_bit_t InvalidEEPCmdErr[1];
	pseudo_bit_t Reserved[10];
};
struct QIB_7220_ErrStatus {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_ErrStatus_pb );
};

#define QIB_7220_ErrClear_offset 0x00000090UL
struct QIB_7220_ErrClear_pb {
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
	pseudo_bit_t RcvEgrFullErrClear[1];
	pseudo_bit_t RcvHdrFullErrClear[1];
	pseudo_bit_t RcvBadTidErrClear[1];
	pseudo_bit_t RcvHdrLenErrClear[1];
	pseudo_bit_t RcvHdrErrClear[1];
	pseudo_bit_t RcvIBLostLinkErrClear[1];
	pseudo_bit_t Reserved1[9];
	pseudo_bit_t SendSpecialTriggerErrClear[1];
	pseudo_bit_t SDmaDisabledErrClear[1];
	pseudo_bit_t SendMinPktLenErrClear[1];
	pseudo_bit_t SendMaxPktLenErrClear[1];
	pseudo_bit_t SendUnderRunErrClear[1];
	pseudo_bit_t SendPktLenErrClear[1];
	pseudo_bit_t SendDroppedSmpPktErrClear[1];
	pseudo_bit_t SendDroppedDataPktErrClear[1];
	pseudo_bit_t SendPioArmLaunchErrClear[1];
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
	pseudo_bit_t IBStatusChangedClear[1];
	pseudo_bit_t InvalidAddrErrClear[1];
	pseudo_bit_t ResetNegatedClear[1];
	pseudo_bit_t HardwareErrClear[1];
	pseudo_bit_t SDmaDescAddrMisalignErrClear[1];
	pseudo_bit_t InvalidEEPCmdErrClear[1];
	pseudo_bit_t Reserved[10];
};
struct QIB_7220_ErrClear {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_ErrClear_pb );
};

#define QIB_7220_HwErrMask_offset 0x00000098UL
struct QIB_7220_HwErrMask_pb {
	pseudo_bit_t PCIeMemParityErrMask[8];
	pseudo_bit_t Reserved3[20];
	pseudo_bit_t SDmaMemReadErrMask[1];
	pseudo_bit_t PoisonedTLPMask[1];
	pseudo_bit_t PcieCplTimeoutMask[1];
	pseudo_bit_t PCIeBusParityErrMask[3];
	pseudo_bit_t Reserved2[2];
	pseudo_bit_t PCIEOct0_uC_MemoryParityErrMask[1];
	pseudo_bit_t PCIEOct1_uC_MemoryParityErrMask[1];
	pseudo_bit_t IB_uC_MemoryParityErrMask[1];
	pseudo_bit_t DDSRXEQMemoryParityErrMask[1];
	pseudo_bit_t TXEMemParityErrMask[4];
	pseudo_bit_t RXEMemParityErrMask[7];
	pseudo_bit_t Reserved1[3];
	pseudo_bit_t PowerOnBISTFailedMask[1];
	pseudo_bit_t Reserved[1];
	pseudo_bit_t PCIESerdesQ0PClkNotDetectMask[1];
	pseudo_bit_t PCIESerdesQ1PClkNotDetectMask[1];
	pseudo_bit_t PCIESerdesQ2PClkNotDetectMask[1];
	pseudo_bit_t PCIESerdesQ3PClkNotDetectMask[1];
	pseudo_bit_t IBSerdesPClkNotDetectMask[1];
	pseudo_bit_t Clk_uC_PLLNotLockedMask[1];
	pseudo_bit_t IBCBusToSPCParityErrMask[1];
	pseudo_bit_t IBCBusFromSPCParityErrMask[1];
};
struct QIB_7220_HwErrMask {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_HwErrMask_pb );
};

#define QIB_7220_HwErrStatus_offset 0x000000a0UL
struct QIB_7220_HwErrStatus_pb {
	pseudo_bit_t PCIeMemParity[8];
	pseudo_bit_t Reserved3[20];
	pseudo_bit_t SDmaMemReadErr[1];
	pseudo_bit_t PoisenedTLP[1];
	pseudo_bit_t PcieCplTimeout[1];
	pseudo_bit_t PCIeBusParity[3];
	pseudo_bit_t Reserved2[2];
	pseudo_bit_t PCIE_uC_Oct0MemoryParityErr[1];
	pseudo_bit_t PCIE_uC_Oct1MemoryParityErr[1];
	pseudo_bit_t IB_uC_MemoryParityErr[1];
	pseudo_bit_t DDSRXEQMemoryParityErr[1];
	pseudo_bit_t TXEMemParity[4];
	pseudo_bit_t RXEMemParity[7];
	pseudo_bit_t Reserved1[3];
	pseudo_bit_t PowerOnBISTFailed[1];
	pseudo_bit_t Reserved[1];
	pseudo_bit_t PCIESerdesQ0PClkNotDetect[1];
	pseudo_bit_t PCIESerdesQ1PClkNotDetect[1];
	pseudo_bit_t PCIESerdesQ2PClkNotDetect[1];
	pseudo_bit_t PCIESerdesQ3PClkNotDetect[1];
	pseudo_bit_t IBSerdesPClkNotDetect[1];
	pseudo_bit_t Clk_uC_PLLNotLocked[1];
	pseudo_bit_t IBCBusToSPCParityErr[1];
	pseudo_bit_t IBCBusFromSPCParityErr[1];
};
struct QIB_7220_HwErrStatus {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_HwErrStatus_pb );
};

#define QIB_7220_HwErrClear_offset 0x000000a8UL
struct QIB_7220_HwErrClear_pb {
	pseudo_bit_t PCIeMemParityClr[8];
	pseudo_bit_t Reserved3[20];
	pseudo_bit_t SDmaMemReadErrClear[1];
	pseudo_bit_t PoisonedTLPClear[1];
	pseudo_bit_t PcieCplTimeoutClear[1];
	pseudo_bit_t PCIeBusParityClr[3];
	pseudo_bit_t Reserved2[2];
	pseudo_bit_t PCIE_uC_Oct0MemoryParityErrClear[1];
	pseudo_bit_t PCIE_uC_Oct1MemoryParityErrClear[1];
	pseudo_bit_t IB_uC_MemoryParityErrClear[1];
	pseudo_bit_t DDSRXEQMemoryParityErrClear[1];
	pseudo_bit_t TXEMemParityClear[4];
	pseudo_bit_t RXEMemParityClear[7];
	pseudo_bit_t Reserved1[3];
	pseudo_bit_t PowerOnBISTFailedClear[1];
	pseudo_bit_t Reserved[1];
	pseudo_bit_t PCIESerdesQ0PClkNotDetectClear[1];
	pseudo_bit_t PCIESerdesQ1PClkNotDetectClear[1];
	pseudo_bit_t PCIESerdesQ2PClkNotDetectClear[1];
	pseudo_bit_t PCIESerdesQ3PClkNotDetectClear[1];
	pseudo_bit_t IBSerdesPClkNotDetectClear[1];
	pseudo_bit_t Clk_uC_PLLNotLockedClear[1];
	pseudo_bit_t IBCBusToSPCparityErrClear[1];
	pseudo_bit_t IBCBusFromSPCParityErrClear[1];
};
struct QIB_7220_HwErrClear {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_HwErrClear_pb );
};

#define QIB_7220_HwDiagCtrl_offset 0x000000b0UL
struct QIB_7220_HwDiagCtrl_pb {
	pseudo_bit_t forcePCIeMemParity[8];
	pseudo_bit_t Reserved2[23];
	pseudo_bit_t forcePCIeBusParity[4];
	pseudo_bit_t Reserved1[1];
	pseudo_bit_t ForcePCIE_uC_Oct0MemoryParityErr[1];
	pseudo_bit_t ForcePCIE_uC_Oct1MemoryParityErr[1];
	pseudo_bit_t ForceIB_uC_MemoryParityErr[1];
	pseudo_bit_t ForceDDSRXEQMemoryParityErr[1];
	pseudo_bit_t ForceTxMemparityErr[4];
	pseudo_bit_t ForceRxMemParityErr[7];
	pseudo_bit_t Reserved[9];
	pseudo_bit_t CounterDisable[1];
	pseudo_bit_t CounterWrEnable[1];
	pseudo_bit_t ForceIBCBusToSPCParityErr[1];
	pseudo_bit_t ForceIBCBusFromSPCParityErr[1];
};
struct QIB_7220_HwDiagCtrl {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_HwDiagCtrl_pb );
};

#define QIB_7220_REG_0000B8_offset 0x000000b8UL

#define QIB_7220_IBCStatus_offset 0x000000c0UL
struct QIB_7220_IBCStatus_pb {
	pseudo_bit_t LinkTrainingState[5];
	pseudo_bit_t LinkState[3];
	pseudo_bit_t LinkSpeedActive[1];
	pseudo_bit_t LinkWidthActive[1];
	pseudo_bit_t DDS_RXEQ_FAIL[1];
	pseudo_bit_t IB_SERDES_TRIM_DONE[1];
	pseudo_bit_t IBRxLaneReversed[1];
	pseudo_bit_t IBTxLaneReversed[1];
	pseudo_bit_t Reserved[16];
	pseudo_bit_t TxReady[1];
	pseudo_bit_t TxCreditOk[1];
	pseudo_bit_t _unused_0[32];
};
struct QIB_7220_IBCStatus {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_IBCStatus_pb );
};

#define QIB_7220_IBCCtrl_offset 0x000000c8UL
struct QIB_7220_IBCCtrl_pb {
	pseudo_bit_t FlowCtrlPeriod[8];
	pseudo_bit_t FlowCtrlWaterMark[8];
	pseudo_bit_t LinkInitCmd[3];
	pseudo_bit_t LinkCmd[2];
	pseudo_bit_t MaxPktLen[11];
	pseudo_bit_t PhyerrThreshold[4];
	pseudo_bit_t OverrunThreshold[4];
	pseudo_bit_t CreditScale[3];
	pseudo_bit_t Reserved[19];
	pseudo_bit_t LinkDownDefaultState[1];
	pseudo_bit_t Loopback[1];
};
struct QIB_7220_IBCCtrl {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_IBCCtrl_pb );
};

#define QIB_7220_EXTStatus_offset 0x000000d0UL
struct QIB_7220_EXTStatus_pb {
	pseudo_bit_t Reserved2[14];
	pseudo_bit_t MemBISTEndTest[1];
	pseudo_bit_t MemBISTDisabled[1];
	pseudo_bit_t Reserved1[16];
	pseudo_bit_t Reserved[16];
	pseudo_bit_t GPIOIn[16];
};
struct QIB_7220_EXTStatus {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_EXTStatus_pb );
};

#define QIB_7220_EXTCtrl_offset 0x000000d8UL
struct QIB_7220_EXTCtrl_pb {
	pseudo_bit_t LEDGblErrRedOff[1];
	pseudo_bit_t LEDGblOkGreenOn[1];
	pseudo_bit_t LEDPriPortYellowOn[1];
	pseudo_bit_t LEDPriPortGreenOn[1];
	pseudo_bit_t Reserved[28];
	pseudo_bit_t GPIOInvert[16];
	pseudo_bit_t GPIOOe[16];
};
struct QIB_7220_EXTCtrl {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_EXTCtrl_pb );
};

#define QIB_7220_GPIOOut_offset 0x000000e0UL

#define QIB_7220_GPIOMask_offset 0x000000e8UL

#define QIB_7220_GPIOStatus_offset 0x000000f0UL

#define QIB_7220_GPIOClear_offset 0x000000f8UL

#define QIB_7220_RcvCtrl_offset 0x00000100UL
struct QIB_7220_RcvCtrl_pb {
	pseudo_bit_t PortEnable[17];
	pseudo_bit_t IntrAvail[17];
	pseudo_bit_t RcvPartitionKeyDisable[1];
	pseudo_bit_t TailUpd[1];
	pseudo_bit_t PortCfg[2];
	pseudo_bit_t RcvQPMapEnable[1];
	pseudo_bit_t Reserved[25];
};
struct QIB_7220_RcvCtrl {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_RcvCtrl_pb );
};

#define QIB_7220_RcvBTHQP_offset 0x00000108UL
struct QIB_7220_RcvBTHQP_pb {
	pseudo_bit_t RcvBTHQP[24];
	pseudo_bit_t Reserved[8];
	pseudo_bit_t _unused_0[32];
};
struct QIB_7220_RcvBTHQP {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_RcvBTHQP_pb );
};

#define QIB_7220_RcvHdrSize_offset 0x00000110UL

#define QIB_7220_RcvHdrCnt_offset 0x00000118UL

#define QIB_7220_RcvHdrEntSize_offset 0x00000120UL

#define QIB_7220_RcvTIDBase_offset 0x00000128UL

#define QIB_7220_RcvTIDCnt_offset 0x00000130UL

#define QIB_7220_RcvEgrBase_offset 0x00000138UL

#define QIB_7220_RcvEgrCnt_offset 0x00000140UL

#define QIB_7220_RcvBufBase_offset 0x00000148UL

#define QIB_7220_RcvBufSize_offset 0x00000150UL

#define QIB_7220_RxIntMemBase_offset 0x00000158UL

#define QIB_7220_RxIntMemSize_offset 0x00000160UL

#define QIB_7220_RcvPartitionKey_offset 0x00000168UL

#define QIB_7220_RcvQPMulticastPort_offset 0x00000170UL
struct QIB_7220_RcvQPMulticastPort_pb {
	pseudo_bit_t RcvQpMcPort[5];
	pseudo_bit_t Reserved[59];
};
struct QIB_7220_RcvQPMulticastPort {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_RcvQPMulticastPort_pb );
};

#define QIB_7220_RcvPktLEDCnt_offset 0x00000178UL
struct QIB_7220_RcvPktLEDCnt_pb {
	pseudo_bit_t OFFperiod[32];
	pseudo_bit_t ONperiod[32];
};
struct QIB_7220_RcvPktLEDCnt {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_RcvPktLEDCnt_pb );
};

#define QIB_7220_IBCDDRCtrl_offset 0x00000180UL
struct QIB_7220_IBCDDRCtrl_pb {
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
	pseudo_bit_t Reserved[5];
	pseudo_bit_t IB_DLID[16];
	pseudo_bit_t IB_DLID_MASK[16];
};
struct QIB_7220_IBCDDRCtrl {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_IBCDDRCtrl_pb );
};

#define QIB_7220_HRTBT_GUID_offset 0x00000188UL

#define QIB_7220_IB_SDTEST_IF_TX_offset 0x00000190UL
struct QIB_7220_IB_SDTEST_IF_TX_pb {
	pseudo_bit_t TS_T_TX_VALID[1];
	pseudo_bit_t TS_3_TX_VALID[1];
	pseudo_bit_t Reserved1[9];
	pseudo_bit_t TS_TX_OPCODE[2];
	pseudo_bit_t TS_TX_SPEED[3];
	pseudo_bit_t Reserved[16];
	pseudo_bit_t TS_TX_TX_CFG[16];
	pseudo_bit_t TS_TX_RX_CFG[16];
};
struct QIB_7220_IB_SDTEST_IF_TX {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_IB_SDTEST_IF_TX_pb );
};

#define QIB_7220_IB_SDTEST_IF_RX_offset 0x00000198UL
struct QIB_7220_IB_SDTEST_IF_RX_pb {
	pseudo_bit_t TS_T_RX_VALID[1];
	pseudo_bit_t TS_3_RX_VALID[1];
	pseudo_bit_t Reserved[14];
	pseudo_bit_t TS_RX_A[8];
	pseudo_bit_t TS_RX_B[8];
	pseudo_bit_t TS_RX_TX_CFG[16];
	pseudo_bit_t TS_RX_RX_CFG[16];
};
struct QIB_7220_IB_SDTEST_IF_RX {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_IB_SDTEST_IF_RX_pb );
};

#define QIB_7220_IBCDDRCtrl2_offset 0x000001a0UL
struct QIB_7220_IBCDDRCtrl2_pb {
	pseudo_bit_t IB_FRONT_PORCH[5];
	pseudo_bit_t IB_BACK_PORCH[5];
	pseudo_bit_t _unused_0[54];
};
struct QIB_7220_IBCDDRCtrl2 {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_IBCDDRCtrl2_pb );
};

#define QIB_7220_IBCDDRStatus_offset 0x000001a8UL
struct QIB_7220_IBCDDRStatus_pb {
	pseudo_bit_t LinkRoundTripLatency[26];
	pseudo_bit_t ReqDDSLocalFromRmt[4];
	pseudo_bit_t RxEqLocalDevice[2];
	pseudo_bit_t heartbeat_crosstalk[4];
	pseudo_bit_t heartbeat_timed_out[1];
	pseudo_bit_t _unused_0[27];
};
struct QIB_7220_IBCDDRStatus {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_IBCDDRStatus_pb );
};

#define QIB_7220_JIntReload_offset 0x000001b0UL
struct QIB_7220_JIntReload_pb {
	pseudo_bit_t J_reload[16];
	pseudo_bit_t J_limit_reload[16];
	pseudo_bit_t _unused_0[32];
};
struct QIB_7220_JIntReload {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_JIntReload_pb );
};

#define QIB_7220_IBNCModeCtrl_offset 0x000001b8UL
struct QIB_7220_IBNCModeCtrl_pb {
	pseudo_bit_t TSMEnable_send_TS1[1];
	pseudo_bit_t TSMEnable_send_TS2[1];
	pseudo_bit_t TSMEnable_ignore_TSM_on_rx[1];
	pseudo_bit_t Reserved1[5];
	pseudo_bit_t TSMCode_TS1[9];
	pseudo_bit_t TSMCode_TS2[9];
	pseudo_bit_t Reserved[38];
};
struct QIB_7220_IBNCModeCtrl {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_IBNCModeCtrl_pb );
};

#define QIB_7220_SendCtrl_offset 0x000001c0UL
struct QIB_7220_SendCtrl_pb {
	pseudo_bit_t Abort[1];
	pseudo_bit_t SendIntBufAvail[1];
	pseudo_bit_t SendBufAvailUpd[1];
	pseudo_bit_t SPioEnable[1];
	pseudo_bit_t SSpecialTriggerEn[1];
	pseudo_bit_t Reserved2[4];
	pseudo_bit_t SDmaIntEnable[1];
	pseudo_bit_t SDmaSingleDescriptor[1];
	pseudo_bit_t SDmaEnable[1];
	pseudo_bit_t SDmaHalt[1];
	pseudo_bit_t Reserved1[3];
	pseudo_bit_t DisarmPIOBuf[8];
	pseudo_bit_t AvailUpdThld[5];
	pseudo_bit_t Reserved[2];
	pseudo_bit_t Disarm[1];
	pseudo_bit_t _unused_0[32];
};
struct QIB_7220_SendCtrl {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_SendCtrl_pb );
};

#define QIB_7220_SendBufBase_offset 0x000001c8UL
struct QIB_7220_SendBufBase_pb {
	pseudo_bit_t BaseAddr_SmallPIO[21];
	pseudo_bit_t Reserved1[11];
	pseudo_bit_t BaseAddr_LargePIO[21];
	pseudo_bit_t Reserved[11];
};
struct QIB_7220_SendBufBase {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_SendBufBase_pb );
};

#define QIB_7220_SendBufSize_offset 0x000001d0UL
struct QIB_7220_SendBufSize_pb {
	pseudo_bit_t Size_SmallPIO[12];
	pseudo_bit_t Reserved1[20];
	pseudo_bit_t Size_LargePIO[13];
	pseudo_bit_t Reserved[19];
};
struct QIB_7220_SendBufSize {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_SendBufSize_pb );
};

#define QIB_7220_SendBufCnt_offset 0x000001d8UL
struct QIB_7220_SendBufCnt_pb {
	pseudo_bit_t Num_SmallBuffers[9];
	pseudo_bit_t Reserved1[23];
	pseudo_bit_t Num_LargeBuffers[4];
	pseudo_bit_t Reserved[28];
};
struct QIB_7220_SendBufCnt {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_SendBufCnt_pb );
};

#define QIB_7220_SendBufAvailAddr_offset 0x000001e0UL
struct QIB_7220_SendBufAvailAddr_pb {
	pseudo_bit_t Reserved[6];
	pseudo_bit_t SendBufAvailAddr[34];
	pseudo_bit_t _unused_0[24];
};
struct QIB_7220_SendBufAvailAddr {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_SendBufAvailAddr_pb );
};

#define QIB_7220_TxIntMemBase_offset 0x000001e8UL

#define QIB_7220_TxIntMemSize_offset 0x000001f0UL

#define QIB_7220_SendDmaBase_offset 0x000001f8UL
struct QIB_7220_SendDmaBase_pb {
	pseudo_bit_t SendDmaBase[48];
	pseudo_bit_t Reserved[16];
};
struct QIB_7220_SendDmaBase {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_SendDmaBase_pb );
};

#define QIB_7220_SendDmaLenGen_offset 0x00000200UL
struct QIB_7220_SendDmaLenGen_pb {
	pseudo_bit_t Length[16];
	pseudo_bit_t Generation[3];
	pseudo_bit_t Reserved[45];
};
struct QIB_7220_SendDmaLenGen {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_SendDmaLenGen_pb );
};

#define QIB_7220_SendDmaTail_offset 0x00000208UL
struct QIB_7220_SendDmaTail_pb {
	pseudo_bit_t SendDmaTail[16];
	pseudo_bit_t Reserved[48];
};
struct QIB_7220_SendDmaTail {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_SendDmaTail_pb );
};

#define QIB_7220_SendDmaHead_offset 0x00000210UL
struct QIB_7220_SendDmaHead_pb {
	pseudo_bit_t SendDmaHead[16];
	pseudo_bit_t Reserved1[16];
	pseudo_bit_t InternalSendDmaHead[16];
	pseudo_bit_t Reserved[16];
};
struct QIB_7220_SendDmaHead {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_SendDmaHead_pb );
};

#define QIB_7220_SendDmaHeadAddr_offset 0x00000218UL
struct QIB_7220_SendDmaHeadAddr_pb {
	pseudo_bit_t SendDmaHeadAddr[48];
	pseudo_bit_t Reserved[16];
};
struct QIB_7220_SendDmaHeadAddr {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_SendDmaHeadAddr_pb );
};

#define QIB_7220_SendDmaBufMask0_offset 0x00000220UL
struct QIB_7220_SendDmaBufMask0_pb {
	pseudo_bit_t BufMask_63_0[0];
	pseudo_bit_t _unused_0[64];
};
struct QIB_7220_SendDmaBufMask0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_SendDmaBufMask0_pb );
};

#define QIB_7220_SendDmaStatus_offset 0x00000238UL
struct QIB_7220_SendDmaStatus_pb {
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
	pseudo_bit_t InternalSDmaEnable[1];
	pseudo_bit_t AbortInProg[1];
	pseudo_bit_t ScoreBoardDrainInProg[1];
};
struct QIB_7220_SendDmaStatus {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_SendDmaStatus_pb );
};

#define QIB_7220_SendBufErr0_offset 0x00000240UL
struct QIB_7220_SendBufErr0_pb {
	pseudo_bit_t SendBufErr_63_0[0];
	pseudo_bit_t _unused_0[64];
};
struct QIB_7220_SendBufErr0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_SendBufErr0_pb );
};

#define QIB_7220_REG_000258_offset 0x00000258UL

#define QIB_7220_AvailUpdCount_offset 0x00000268UL
struct QIB_7220_AvailUpdCount_pb {
	pseudo_bit_t AvailUpdCount[5];
	pseudo_bit_t _unused_0[59];
};
struct QIB_7220_AvailUpdCount {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_AvailUpdCount_pb );
};

#define QIB_7220_RcvHdrAddr0_offset 0x00000270UL
struct QIB_7220_RcvHdrAddr0_pb {
	pseudo_bit_t Reserved[2];
	pseudo_bit_t RcvHdrAddr0[38];
	pseudo_bit_t _unused_0[24];
};
struct QIB_7220_RcvHdrAddr0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_RcvHdrAddr0_pb );
};

#define QIB_7220_REG_0002F8_offset 0x000002f8UL

#define QIB_7220_RcvHdrTailAddr0_offset 0x00000300UL
struct QIB_7220_RcvHdrTailAddr0_pb {
	pseudo_bit_t Reserved[2];
	pseudo_bit_t RcvHdrTailAddr0[38];
	pseudo_bit_t _unused_0[24];
};
struct QIB_7220_RcvHdrTailAddr0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_RcvHdrTailAddr0_pb );
};

#define QIB_7220_REG_000388_offset 0x00000388UL

#define QIB_7220_ibsd_epb_access_ctrl_offset 0x000003c0UL
struct QIB_7220_ibsd_epb_access_ctrl_pb {
	pseudo_bit_t sw_ib_epb_req[1];
	pseudo_bit_t Reserved[7];
	pseudo_bit_t sw_ib_epb_req_granted[1];
	pseudo_bit_t _unused_0[55];
};
struct QIB_7220_ibsd_epb_access_ctrl {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_ibsd_epb_access_ctrl_pb );
};

#define QIB_7220_ibsd_epb_transaction_reg_offset 0x000003c8UL
struct QIB_7220_ibsd_epb_transaction_reg_pb {
	pseudo_bit_t ib_epb_data[8];
	pseudo_bit_t ib_epb_address[15];
	pseudo_bit_t Reserved2[1];
	pseudo_bit_t ib_epb_read_write[1];
	pseudo_bit_t ib_epb_cs[2];
	pseudo_bit_t Reserved1[1];
	pseudo_bit_t mem_data_parity[1];
	pseudo_bit_t Reserved[1];
	pseudo_bit_t ib_epb_req_error[1];
	pseudo_bit_t ib_epb_rdy[1];
	pseudo_bit_t _unused_0[32];
};
struct QIB_7220_ibsd_epb_transaction_reg {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_ibsd_epb_transaction_reg_pb );
};

#define QIB_7220_REG_0003D0_offset 0x000003d0UL

#define QIB_7220_XGXSCfg_offset 0x000003d8UL
struct QIB_7220_XGXSCfg_pb {
	pseudo_bit_t tx_rx_reset[1];
	pseudo_bit_t Reserved2[1];
	pseudo_bit_t xcv_reset[1];
	pseudo_bit_t Reserved1[6];
	pseudo_bit_t link_sync_mask[10];
	pseudo_bit_t Reserved[44];
	pseudo_bit_t sel_link_down_for_fctrl_lane_sync_reset[1];
};
struct QIB_7220_XGXSCfg {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_XGXSCfg_pb );
};

#define QIB_7220_IBSerDesCtrl_offset 0x000003e0UL
struct QIB_7220_IBSerDesCtrl_pb {
	pseudo_bit_t ResetIB_uC_Core[1];
	pseudo_bit_t Reserved2[7];
	pseudo_bit_t NumSerDesRegsToWrForDDS[5];
	pseudo_bit_t NumSerDesRegsToWrForRXEQ[5];
	pseudo_bit_t Reserved1[14];
	pseudo_bit_t TXINV[1];
	pseudo_bit_t RXINV[1];
	pseudo_bit_t RXIDLE[1];
	pseudo_bit_t TWC[1];
	pseudo_bit_t TXOBPD[1];
	pseudo_bit_t PLLM[3];
	pseudo_bit_t PLLN[2];
	pseudo_bit_t CKSEL_uC[2];
	pseudo_bit_t INT_uC[1];
	pseudo_bit_t Reserved[19];
};
struct QIB_7220_IBSerDesCtrl {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_IBSerDesCtrl_pb );
};

#define QIB_7220_EEPCtlStat_offset 0x000003e8UL
struct QIB_7220_EEPCtlStat_pb {
	pseudo_bit_t EPAccEn[2];
	pseudo_bit_t EPReset[1];
	pseudo_bit_t ByteProg[1];
	pseudo_bit_t PageMode[1];
	pseudo_bit_t LstDatWr[1];
	pseudo_bit_t CmdWrErr[1];
	pseudo_bit_t Reserved[24];
	pseudo_bit_t CtlrStat[1];
	pseudo_bit_t _unused_0[32];
};
struct QIB_7220_EEPCtlStat {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_EEPCtlStat_pb );
};

#define QIB_7220_EEPAddrCmd_offset 0x000003f0UL
struct QIB_7220_EEPAddrCmd_pb {
	pseudo_bit_t EPAddr[24];
	pseudo_bit_t EPCmd[8];
	pseudo_bit_t _unused_0[32];
};
struct QIB_7220_EEPAddrCmd {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_EEPAddrCmd_pb );
};

#define QIB_7220_EEPData_offset 0x000003f8UL

#define QIB_7220_pciesd_epb_access_ctrl_offset 0x00000400UL
struct QIB_7220_pciesd_epb_access_ctrl_pb {
	pseudo_bit_t sw_pcie_epb_req[1];
	pseudo_bit_t sw_pcieepb_star_en[2];
	pseudo_bit_t Reserved[5];
	pseudo_bit_t sw_pcie_epb_req_granted[1];
	pseudo_bit_t _unused_0[55];
};
struct QIB_7220_pciesd_epb_access_ctrl {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_pciesd_epb_access_ctrl_pb );
};

#define QIB_7220_pciesd_epb_transaction_reg_offset 0x00000408UL
struct QIB_7220_pciesd_epb_transaction_reg_pb {
	pseudo_bit_t pcie_epb_data[8];
	pseudo_bit_t pcie_epb_address[15];
	pseudo_bit_t Reserved1[1];
	pseudo_bit_t pcie_epb_read_write[1];
	pseudo_bit_t pcie_epb_cs[3];
	pseudo_bit_t mem_data_parity[1];
	pseudo_bit_t Reserved[1];
	pseudo_bit_t pcie_epb_req_error[1];
	pseudo_bit_t pcie_epb_rdy[1];
	pseudo_bit_t _unused_0[32];
};
struct QIB_7220_pciesd_epb_transaction_reg {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_pciesd_epb_transaction_reg_pb );
};

#define QIB_7220_efuse_control_reg_offset 0x00000410UL
struct QIB_7220_efuse_control_reg_pb {
	pseudo_bit_t start_op[1];
	pseudo_bit_t operation[1];
	pseudo_bit_t read_valid[1];
	pseudo_bit_t req_error[1];
	pseudo_bit_t Reserved[27];
	pseudo_bit_t rdy[1];
	pseudo_bit_t _unused_0[32];
};
struct QIB_7220_efuse_control_reg {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_efuse_control_reg_pb );
};

#define QIB_7220_efuse_rddata0_reg_offset 0x00000418UL

#define QIB_7220_procmon_register_offset 0x00000438UL
struct QIB_7220_procmon_register_pb {
	pseudo_bit_t interval_time[12];
	pseudo_bit_t Reserved1[2];
	pseudo_bit_t clear_counter[1];
	pseudo_bit_t start_counter[1];
	pseudo_bit_t procmon_count[9];
	pseudo_bit_t Reserved[6];
	pseudo_bit_t procmon_count_valid[1];
	pseudo_bit_t _unused_0[32];
};
struct QIB_7220_procmon_register {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_procmon_register_pb );
};

#define QIB_7220_PcieRbufTestReg0_offset 0x00000440UL

#define QIB_7220_PcieRBufTestReg1_offset 0x00000448UL

#define QIB_7220_SPC_JTAG_ACCESS_REG_offset 0x00000460UL
struct QIB_7220_SPC_JTAG_ACCESS_REG_pb {
	pseudo_bit_t rdy[1];
	pseudo_bit_t tdo[1];
	pseudo_bit_t tdi[1];
	pseudo_bit_t opcode[2];
	pseudo_bit_t bist_en[5];
	pseudo_bit_t SPC_JTAG_ACCESS_EN[1];
	pseudo_bit_t _unused_0[53];
};
struct QIB_7220_SPC_JTAG_ACCESS_REG {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_SPC_JTAG_ACCESS_REG_pb );
};

#define QIB_7220_LAControlReg_offset 0x00000468UL
struct QIB_7220_LAControlReg_pb {
	pseudo_bit_t Finished[1];
	pseudo_bit_t Address[8];
	pseudo_bit_t Mode[2];
	pseudo_bit_t Delay[20];
	pseudo_bit_t Reserved[1];
	pseudo_bit_t _unused_0[32];
};
struct QIB_7220_LAControlReg {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_LAControlReg_pb );
};

#define QIB_7220_GPIODebugSelReg_offset 0x00000470UL
struct QIB_7220_GPIODebugSelReg_pb {
	pseudo_bit_t GPIOSourceSelDebug[16];
	pseudo_bit_t SelPulse[16];
	pseudo_bit_t _unused_0[32];
};
struct QIB_7220_GPIODebugSelReg {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_GPIODebugSelReg_pb );
};

#define QIB_7220_DebugPortValueReg_offset 0x00000478UL

#define QIB_7220_SendDmaBufUsed0_offset 0x00000480UL
struct QIB_7220_SendDmaBufUsed0_pb {
	pseudo_bit_t BufUsed_63_0[0];
	pseudo_bit_t _unused_0[64];
};
struct QIB_7220_SendDmaBufUsed0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_SendDmaBufUsed0_pb );
};

#define QIB_7220_SendDmaReqTagUsed_offset 0x00000498UL
struct QIB_7220_SendDmaReqTagUsed_pb {
	pseudo_bit_t ReqTagUsed_7_0[8];
	pseudo_bit_t _unused_0[8];
	pseudo_bit_t Reserved[48];
};
struct QIB_7220_SendDmaReqTagUsed {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_SendDmaReqTagUsed_pb );
};

#define QIB_7220_efuse_pgm_data0_offset 0x000004a0UL

#define QIB_7220_MEM_0004B0_offset 0x000004b0UL

#define QIB_7220_SerDes_DDSRXEQ0_offset 0x00000500UL
struct QIB_7220_SerDes_DDSRXEQ0_pb {
	pseudo_bit_t element_num[4];
	pseudo_bit_t reg_addr[6];
	pseudo_bit_t _unused_0[54];
};
struct QIB_7220_SerDes_DDSRXEQ0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_SerDes_DDSRXEQ0_pb );
};

#define QIB_7220_MEM_0005F0_offset 0x000005f0UL

#define QIB_7220_LAMemory_offset 0x00000600UL

#define QIB_7220_MEM_0007F0_offset 0x000007f0UL

#define QIB_7220_SendBufAvail0_offset 0x00001000UL
struct QIB_7220_SendBufAvail0_pb {
	pseudo_bit_t SendBuf_31_0[0];
	pseudo_bit_t _unused_0[64];
};
struct QIB_7220_SendBufAvail0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_SendBufAvail0_pb );
};

#define QIB_7220_MEM_001028_offset 0x00001028UL

#define QIB_7220_LBIntCnt_offset 0x00013000UL

#define QIB_7220_LBFlowStallCnt_offset 0x00013008UL

#define QIB_7220_TxSDmaDescCnt_offset 0x00013010UL

#define QIB_7220_TxUnsupVLErrCnt_offset 0x00013018UL

#define QIB_7220_TxDataPktCnt_offset 0x00013020UL

#define QIB_7220_TxFlowPktCnt_offset 0x00013028UL

#define QIB_7220_TxDwordCnt_offset 0x00013030UL

#define QIB_7220_TxLenErrCnt_offset 0x00013038UL

#define QIB_7220_TxMaxMinLenErrCnt_offset 0x00013040UL

#define QIB_7220_TxUnderrunCnt_offset 0x00013048UL

#define QIB_7220_TxFlowStallCnt_offset 0x00013050UL

#define QIB_7220_TxDroppedPktCnt_offset 0x00013058UL

#define QIB_7220_RxDroppedPktCnt_offset 0x00013060UL

#define QIB_7220_RxDataPktCnt_offset 0x00013068UL

#define QIB_7220_RxFlowPktCnt_offset 0x00013070UL

#define QIB_7220_RxDwordCnt_offset 0x00013078UL

#define QIB_7220_RxLenErrCnt_offset 0x00013080UL

#define QIB_7220_RxMaxMinLenErrCnt_offset 0x00013088UL

#define QIB_7220_RxICRCErrCnt_offset 0x00013090UL

#define QIB_7220_RxVCRCErrCnt_offset 0x00013098UL

#define QIB_7220_RxFlowCtrlViolCnt_offset 0x000130a0UL

#define QIB_7220_RxVersionErrCnt_offset 0x000130a8UL

#define QIB_7220_RxLinkMalformCnt_offset 0x000130b0UL

#define QIB_7220_RxEBPCnt_offset 0x000130b8UL

#define QIB_7220_RxLPCRCErrCnt_offset 0x000130c0UL

#define QIB_7220_RxBufOvflCnt_offset 0x000130c8UL

#define QIB_7220_RxTIDFullErrCnt_offset 0x000130d0UL

#define QIB_7220_RxTIDValidErrCnt_offset 0x000130d8UL

#define QIB_7220_RxPKeyMismatchCnt_offset 0x000130e0UL

#define QIB_7220_RxP0HdrEgrOvflCnt_offset 0x000130e8UL

#define QIB_7220_IBStatusChangeCnt_offset 0x00013170UL

#define QIB_7220_IBLinkErrRecoveryCnt_offset 0x00013178UL

#define QIB_7220_IBLinkDownedCnt_offset 0x00013180UL

#define QIB_7220_IBSymbolErrCnt_offset 0x00013188UL

#define QIB_7220_RxVL15DroppedPktCnt_offset 0x00013190UL

#define QIB_7220_RxOtherLocalPhyErrCnt_offset 0x00013198UL

#define QIB_7220_PcieRetryBufDiagQwordCnt_offset 0x000131a0UL

#define QIB_7220_ExcessBufferOvflCnt_offset 0x000131a8UL

#define QIB_7220_LocalLinkIntegrityErrCnt_offset 0x000131b0UL

#define QIB_7220_RxVlErrCnt_offset 0x000131b8UL

#define QIB_7220_RxDlidFltrCnt_offset 0x000131c0UL

#define QIB_7220_CNT_0131C8_offset 0x000131c8UL

#define QIB_7220_PSStat_offset 0x00013200UL

#define QIB_7220_PSStart_offset 0x00013208UL

#define QIB_7220_PSInterval_offset 0x00013210UL

#define QIB_7220_PSRcvDataCount_offset 0x00013218UL

#define QIB_7220_PSRcvPktsCount_offset 0x00013220UL

#define QIB_7220_PSXmitDataCount_offset 0x00013228UL

#define QIB_7220_PSXmitPktsCount_offset 0x00013230UL

#define QIB_7220_PSXmitWaitCount_offset 0x00013238UL

#define QIB_7220_CNT_013240_offset 0x00013240UL

#define QIB_7220_RcvEgrArray_offset 0x00014000UL

#define QIB_7220_MEM_038000_offset 0x00038000UL

#define QIB_7220_RcvTIDArray0_offset 0x00053000UL

#define QIB_7220_PIOLaunchFIFO_offset 0x00064000UL

#define QIB_7220_MEM_064480_offset 0x00064480UL

#define QIB_7220_SendPIOpbcCache_offset 0x00064800UL

#define QIB_7220_MEM_064C80_offset 0x00064c80UL

#define QIB_7220_PreLaunchFIFO_offset 0x00065000UL

#define QIB_7220_MEM_065080_offset 0x00065080UL

#define QIB_7220_ScoreBoard_offset 0x00065400UL

#define QIB_7220_MEM_065440_offset 0x00065440UL

#define QIB_7220_DescriptorFIFO_offset 0x00065800UL

#define QIB_7220_MEM_065880_offset 0x00065880UL

#define QIB_7220_RcvBuf1_offset 0x00072000UL

#define QIB_7220_MEM_074800_offset 0x00074800UL

#define QIB_7220_RcvBuf2_offset 0x00075000UL

#define QIB_7220_MEM_076400_offset 0x00076400UL

#define QIB_7220_RcvFlags_offset 0x00077000UL

#define QIB_7220_MEM_078400_offset 0x00078400UL

#define QIB_7220_RcvLookupBuf1_offset 0x00079000UL

#define QIB_7220_MEM_07A400_offset 0x0007a400UL

#define QIB_7220_RcvDMADatBuf_offset 0x0007b000UL

#define QIB_7220_RcvDMAHdrBuf_offset 0x0007b800UL

#define QIB_7220_MiscRXEIntMem_offset 0x0007c000UL

#define QIB_7220_MEM_07D400_offset 0x0007d400UL

#define QIB_7220_PCIERcvBuf_offset 0x00080000UL

#define QIB_7220_PCIERetryBuf_offset 0x00084000UL

#define QIB_7220_PCIERcvBufRdToWrAddr_offset 0x00088000UL

#define QIB_7220_PCIECplBuf_offset 0x00090000UL

#define QIB_7220_IBSerDesMappTable_offset 0x00094000UL

#define QIB_7220_MEM_095000_offset 0x00095000UL

#define QIB_7220_SendBuf0_MA_offset 0x00100000UL

#define QIB_7220_MEM_1A0000_offset 0x001a0000UL

#define QIB_7220_RcvHdrTail0_offset 0x00200000UL

#define QIB_7220_RcvHdrHead0_offset 0x00200008UL
struct QIB_7220_RcvHdrHead0_pb {
	pseudo_bit_t RcvHeadPointer[32];
	pseudo_bit_t counter[16];
	pseudo_bit_t Reserved[16];
};
struct QIB_7220_RcvHdrHead0 {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_RcvHdrHead0_pb );
};

#define QIB_7220_RcvEgrIndexTail0_offset 0x00200010UL

#define QIB_7220_RcvEgrIndexHead0_offset 0x00200018UL

#define QIB_7220_MEM_200020_offset 0x00200020UL

#define QIB_7220_RcvHdrTail1_offset 0x00210000UL

#define QIB_7220_RcvHdrHead1_offset 0x00210008UL
struct QIB_7220_RcvHdrHead1_pb {
	pseudo_bit_t RcvHeadPointer[32];
	pseudo_bit_t counter[16];
	pseudo_bit_t Reserved[16];
};
struct QIB_7220_RcvHdrHead1 {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_RcvHdrHead1_pb );
};

#define QIB_7220_RcvEgrIndexTail1_offset 0x00210010UL

#define QIB_7220_RcvEgrIndexHead1_offset 0x00210018UL

#define QIB_7220_MEM_210020_offset 0x00210020UL

#define QIB_7220_RcvHdrTail2_offset 0x00220000UL

#define QIB_7220_RcvHdrHead2_offset 0x00220008UL
struct QIB_7220_RcvHdrHead2_pb {
	pseudo_bit_t RcvHeadPointer[32];
	pseudo_bit_t counter[16];
	pseudo_bit_t Reserved[16];
};
struct QIB_7220_RcvHdrHead2 {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_RcvHdrHead2_pb );
};

#define QIB_7220_RcvEgrIndexTail2_offset 0x00220010UL

#define QIB_7220_RcvEgrIndexHead2_offset 0x00220018UL

#define QIB_7220_MEM_220020_offset 0x00220020UL

#define QIB_7220_RcvHdrTail3_offset 0x00230000UL

#define QIB_7220_RcvHdrHead3_offset 0x00230008UL
struct QIB_7220_RcvHdrHead3_pb {
	pseudo_bit_t RcvHeadPointer[32];
	pseudo_bit_t counter[16];
	pseudo_bit_t Reserved[16];
};
struct QIB_7220_RcvHdrHead3 {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_RcvHdrHead3_pb );
};

#define QIB_7220_RcvEgrIndexTail3_offset 0x00230010UL

#define QIB_7220_RcvEgrIndexHead3_offset 0x00230018UL

#define QIB_7220_MEM_230020_offset 0x00230020UL

#define QIB_7220_RcvHdrTail4_offset 0x00240000UL

#define QIB_7220_RcvHdrHead4_offset 0x00240008UL
struct QIB_7220_RcvHdrHead4_pb {
	pseudo_bit_t RcvHeadPointer[32];
	pseudo_bit_t counter[16];
	pseudo_bit_t Reserved[16];
};
struct QIB_7220_RcvHdrHead4 {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_RcvHdrHead4_pb );
};

#define QIB_7220_RcvEgrIndexTail4_offset 0x00240010UL

#define QIB_7220_RcvEgrIndexHead4_offset 0x00240018UL

#define QIB_7220_MEM_240020_offset 0x00240020UL

#define QIB_7220_RcvHdrTail5_offset 0x00250000UL

#define QIB_7220_RcvHdrHead5_offset 0x00250008UL
struct QIB_7220_RcvHdrHead5_pb {
	pseudo_bit_t RcvHeadPointer[32];
	pseudo_bit_t counter[16];
	pseudo_bit_t Reserved[16];
};
struct QIB_7220_RcvHdrHead5 {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_RcvHdrHead5_pb );
};

#define QIB_7220_RcvEgrIndexTail5_offset 0x00250010UL

#define QIB_7220_RcvEgrIndexHead5_offset 0x00250018UL

#define QIB_7220_MEM_250020_offset 0x00250020UL

#define QIB_7220_RcvHdrTail6_offset 0x00260000UL

#define QIB_7220_RcvHdrHead6_offset 0x00260008UL
struct QIB_7220_RcvHdrHead6_pb {
	pseudo_bit_t RcvHeadPointer[32];
	pseudo_bit_t counter[16];
	pseudo_bit_t Reserved[16];
};
struct QIB_7220_RcvHdrHead6 {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_RcvHdrHead6_pb );
};

#define QIB_7220_RcvEgrIndexTail6_offset 0x00260010UL

#define QIB_7220_RcvEgrIndexHead6_offset 0x00260018UL

#define QIB_7220_MEM_260020_offset 0x00260020UL

#define QIB_7220_RcvHdrTail7_offset 0x00270000UL

#define QIB_7220_RcvHdrHead7_offset 0x00270008UL
struct QIB_7220_RcvHdrHead7_pb {
	pseudo_bit_t RcvHeadPointer[32];
	pseudo_bit_t counter[16];
	pseudo_bit_t Reserved[16];
};
struct QIB_7220_RcvHdrHead7 {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_RcvHdrHead7_pb );
};

#define QIB_7220_RcvEgrIndexTail7_offset 0x00270010UL

#define QIB_7220_RcvEgrIndexHead7_offset 0x00270018UL

#define QIB_7220_MEM_270020_offset 0x00270020UL

#define QIB_7220_RcvHdrTail8_offset 0x00280000UL

#define QIB_7220_RcvHdrHead8_offset 0x00280008UL
struct QIB_7220_RcvHdrHead8_pb {
	pseudo_bit_t RcvHeadPointer[32];
	pseudo_bit_t counter[16];
	pseudo_bit_t Reserved[16];
};
struct QIB_7220_RcvHdrHead8 {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_RcvHdrHead8_pb );
};

#define QIB_7220_RcvEgrIndexTail8_offset 0x00280010UL

#define QIB_7220_RcvEgrIndexHead8_offset 0x00280018UL

#define QIB_7220_MEM_280020_offset 0x00280020UL

#define QIB_7220_RcvHdrTail9_offset 0x00290000UL

#define QIB_7220_RcvHdrHead9_offset 0x00290008UL
struct QIB_7220_RcvHdrHead9_pb {
	pseudo_bit_t RcvHeadPointer[32];
	pseudo_bit_t counter[16];
	pseudo_bit_t Reserved[16];
};
struct QIB_7220_RcvHdrHead9 {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_RcvHdrHead9_pb );
};

#define QIB_7220_RcvEgrIndexTail9_offset 0x00290010UL

#define QIB_7220_RcvEgrIndexHead9_offset 0x00290018UL

#define QIB_7220_MEM_290020_offset 0x00290020UL

#define QIB_7220_RcvHdrTail10_offset 0x002a0000UL

#define QIB_7220_RcvHdrHead10_offset 0x002a0008UL
struct QIB_7220_RcvHdrHead10_pb {
	pseudo_bit_t RcvHeadPointer[32];
	pseudo_bit_t counter[16];
	pseudo_bit_t Reserved[16];
};
struct QIB_7220_RcvHdrHead10 {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_RcvHdrHead10_pb );
};

#define QIB_7220_RcvEgrIndexTail10_offset 0x002a0010UL

#define QIB_7220_RcvEgrIndexHead10_offset 0x002a0018UL

#define QIB_7220_MEM_2A0020_offset 0x002a0020UL

#define QIB_7220_RcvHdrTail11_offset 0x002b0000UL

#define QIB_7220_RcvHdrHead11_offset 0x002b0008UL
struct QIB_7220_RcvHdrHead11_pb {
	pseudo_bit_t RcvHeadPointer[32];
	pseudo_bit_t counter[16];
	pseudo_bit_t Reserved[16];
};
struct QIB_7220_RcvHdrHead11 {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_RcvHdrHead11_pb );
};

#define QIB_7220_RcvEgrIndexTail11_offset 0x002b0010UL

#define QIB_7220_RcvEgrIndexHead11_offset 0x002b0018UL

#define QIB_7220_MEM_2B0020_offset 0x002b0020UL

#define QIB_7220_RcvHdrTail12_offset 0x002c0000UL

#define QIB_7220_RcvHdrHead12_offset 0x002c0008UL
struct QIB_7220_RcvHdrHead12_pb {
	pseudo_bit_t RcvHeadPointer[32];
	pseudo_bit_t counter[16];
	pseudo_bit_t Reserved[16];
};
struct QIB_7220_RcvHdrHead12 {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_RcvHdrHead12_pb );
};

#define QIB_7220_RcvEgrIndexTail12_offset 0x002c0010UL

#define QIB_7220_RcvEgrIndexHead12_offset 0x002c0018UL

#define QIB_7220_MEM_2C0020_offset 0x002c0020UL

#define QIB_7220_RcvHdrTail13_offset 0x002d0000UL

#define QIB_7220_RcvHdrHead13_offset 0x002d0008UL
struct QIB_7220_RcvHdrHead13_pb {
	pseudo_bit_t RcvHeadPointer[32];
	pseudo_bit_t counter[16];
	pseudo_bit_t Reserved[16];
};
struct QIB_7220_RcvHdrHead13 {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_RcvHdrHead13_pb );
};

#define QIB_7220_RcvEgrIndexTail13_offset 0x002d0010UL

#define QIB_7220_RcvEgrIndexHead13_offset 0x002d0018UL

#define QIB_7220_MEM_2D0020_offset 0x002d0020UL

#define QIB_7220_RcvHdrTail14_offset 0x002e0000UL

#define QIB_7220_RcvHdrHead14_offset 0x002e0008UL
struct QIB_7220_RcvHdrHead14_pb {
	pseudo_bit_t RcvHeadPointer[32];
	pseudo_bit_t counter[16];
	pseudo_bit_t Reserved[16];
};
struct QIB_7220_RcvHdrHead14 {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_RcvHdrHead14_pb );
};

#define QIB_7220_RcvEgrIndexTail14_offset 0x002e0010UL

#define QIB_7220_RcvEgrIndexHead14_offset 0x002e0018UL

#define QIB_7220_MEM_2E0020_offset 0x002e0020UL

#define QIB_7220_RcvHdrTail15_offset 0x002f0000UL

#define QIB_7220_RcvHdrHead15_offset 0x002f0008UL
struct QIB_7220_RcvHdrHead15_pb {
	pseudo_bit_t RcvHeadPointer[32];
	pseudo_bit_t counter[16];
	pseudo_bit_t Reserved[16];
};
struct QIB_7220_RcvHdrHead15 {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_RcvHdrHead15_pb );
};

#define QIB_7220_RcvEgrIndexTail15_offset 0x002f0010UL

#define QIB_7220_RcvEgrIndexHead15_offset 0x002f0018UL

#define QIB_7220_MEM_2F0020_offset 0x002f0020UL

#define QIB_7220_RcvHdrTail16_offset 0x00300000UL

#define QIB_7220_RcvHdrHead16_offset 0x00300008UL
struct QIB_7220_RcvHdrHead16_pb {
	pseudo_bit_t RcvHeadPointer[32];
	pseudo_bit_t counter[16];
	pseudo_bit_t Reserved[16];
};
struct QIB_7220_RcvHdrHead16 {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_RcvHdrHead16_pb );
};

#define QIB_7220_RcvEgrIndexTail16_offset 0x00300010UL

#define QIB_7220_RcvEgrIndexHead16_offset 0x00300018UL

#define QIB_7220_MEM_300020_offset 0x00300020UL

