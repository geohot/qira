/* src/prism2/include/prism2/hfa384x.h
*
* Defines the constants and data structures for the hfa384x
*
* Copyright (C) 1999 AbsoluteValue Systems, Inc.  All Rights Reserved.
* --------------------------------------------------------------------
*
* linux-wlan
*
*   The contents of this file are subject to the Mozilla Public
*   License Version 1.1 (the "License"); you may not use this file
*   except in compliance with the License. You may obtain a copy of
*   the License at http://www.mozilla.org/MPL/
*
*   Software distributed under the License is distributed on an "AS
*   IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
*   implied. See the License for the specific language governing
*   rights and limitations under the License.
*
*   Alternatively, the contents of this file may be used under the
*   terms of the GNU Public License version 2 (the "GPL"), in which
*   case the provisions of the GPL are applicable instead of the
*   above.  If you wish to allow the use of your version of this file
*   only under the terms of the GPL and not to allow others to use
*   your version of this file under the MPL, indicate your decision
*   by deleting the provisions above and replace them with the notice
*   and other provisions required by the GPL.  If you do not delete
*   the provisions above, a recipient may use your version of this
*   file under either the MPL or the GPL.
*
* --------------------------------------------------------------------
*
* Inquiries regarding the linux-wlan Open Source project can be
* made directly to:
*
* AbsoluteValue Systems Inc.
* info@linux-wlan.com
* http://www.linux-wlan.com
*
* --------------------------------------------------------------------
*
* Portions of the development of this software were funded by
* Intersil Corporation as part of PRISM(R) chipset product development.
*
* --------------------------------------------------------------------
*
*   [Implementation and usage notes]
*
*   [References]
*	CW10 Programmer's Manual v1.5
*	IEEE 802.11 D10.0
*
* --------------------------------------------------------------------
*/

FILE_LICENCE ( GPL2_ONLY );

#ifndef _HFA384x_H
#define _HFA384x_H

/*=============================================================*/
#define HFA384x_FIRMWARE_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))

#define HFA384x_LEVEL_TO_dBm(v)   (0x100 + (v) * 100 / 255 - 100)

/*------ Constants --------------------------------------------*/
/*--- Mins & Maxs -----------------------------------*/
#define		HFA384x_CMD_ALLOC_LEN_MIN	((uint16_t)4)
#define		HFA384x_CMD_ALLOC_LEN_MAX	((uint16_t)2400)
#define		HFA384x_BAP_DATALEN_MAX		((uint16_t)4096)
#define		HFA384x_BAP_OFFSET_MAX		((uint16_t)4096)
#define		HFA384x_PORTID_MAX		((uint16_t)7)
#define		HFA384x_NUMPORTS_MAX		((uint16_t)(HFA384x_PORTID_MAX+1))
#define		HFA384x_PDR_LEN_MAX		((uint16_t)512)	/* in bytes, from EK */
#define		HFA384x_PDA_RECS_MAX		((uint16_t)200)	/* a guess */
#define		HFA384x_PDA_LEN_MAX		((uint16_t)1024)	/* in bytes, from EK */
#define		HFA384x_SCANRESULT_MAX		((uint16_t)31)
#define		HFA384x_HSCANRESULT_MAX		((uint16_t)31)
#define		HFA384x_CHINFORESULT_MAX	((uint16_t)16)
#define		HFA384x_DRVR_FIDSTACKLEN_MAX	(10)
#define		HFA384x_DRVR_TXBUF_MAX		(sizeof(hfa384x_tx_frame_t) + \
						WLAN_DATA_MAXLEN - \
						WLAN_WEP_IV_LEN - \
						WLAN_WEP_ICV_LEN + 2)
#define		HFA384x_DRVR_MAGIC		(0x4a2d)
#define		HFA384x_INFODATA_MAXLEN		(sizeof(hfa384x_infodata_t))
#define		HFA384x_INFOFRM_MAXLEN		(sizeof(hfa384x_InfFrame_t))
#define		HFA384x_RID_GUESSING_MAXLEN	2048  /* I'm not really sure */
#define		HFA384x_RIDDATA_MAXLEN		HFA384x_RID_GUESSING_MAXLEN
#define		HFA384x_USB_RWMEM_MAXLEN	2048

/*--- Support Constants -----------------------------*/
#define		HFA384x_BAP_PROC			((uint16_t)0)
#define		HFA384x_BAP_int				((uint16_t)1)
#define		HFA384x_PORTTYPE_IBSS			((uint16_t)0)
#define		HFA384x_PORTTYPE_BSS			((uint16_t)1)
#define		HFA384x_PORTTYPE_WDS			((uint16_t)2)
#define		HFA384x_PORTTYPE_PSUEDOIBSS		((uint16_t)3)
#define		HFA384x_PORTTYPE_HOSTAP    		((uint16_t)6)
#define		HFA384x_WEPFLAGS_PRIVINVOKED		((uint16_t)BIT0)
#define		HFA384x_WEPFLAGS_EXCLUDE		((uint16_t)BIT1)
#define		HFA384x_WEPFLAGS_DISABLE_TXCRYPT	((uint16_t)BIT4)
#define		HFA384x_WEPFLAGS_DISABLE_RXCRYPT	((uint16_t)BIT7)
#define		HFA384x_WEPFLAGS_DISALLOW_MIXED 	((uint16_t)BIT11)
#define		HFA384x_WEPFLAGS_IV_INTERVAL1		((uint16_t)0)
#define		HFA384x_WEPFLAGS_IV_INTERVAL10		((uint16_t)BIT5)
#define		HFA384x_WEPFLAGS_IV_INTERVAL50		((uint16_t)BIT6)
#define		HFA384x_WEPFLAGS_IV_INTERVAL100		((uint16_t)(BIT5 | BIT6))
#define		HFA384x_WEPFLAGS_FIRMWARE_WPA  		((uint16_t)BIT8)
#define		HFA384x_WEPFLAGS_HOST_MIC      		((uint16_t)BIT9)
#define 	HFA384x_ROAMMODE_FWSCAN_FWROAM		((uint16_t)1)
#define 	HFA384x_ROAMMODE_FWSCAN_HOSTROAM	((uint16_t)2)
#define 	HFA384x_ROAMMODE_HOSTSCAN_HOSTROAM	((uint16_t)3)
#define 	HFA384x_PORTSTATUS_DISABLED		((uint16_t)1)
#define 	HFA384x_PORTSTATUS_INITSRCH		((uint16_t)2)
#define 	HFA384x_PORTSTATUS_CONN_IBSS		((uint16_t)3)
#define 	HFA384x_PORTSTATUS_CONN_ESS		((uint16_t)4)
#define 	HFA384x_PORTSTATUS_OOR_ESS		((uint16_t)5)
#define 	HFA384x_PORTSTATUS_CONN_WDS		((uint16_t)6)
#define 	HFA384x_PORTSTATUS_HOSTAP		((uint16_t)8)
#define		HFA384x_RATEBIT_1			((uint16_t)1)
#define		HFA384x_RATEBIT_2			((uint16_t)2)
#define		HFA384x_RATEBIT_5dot5			((uint16_t)4)
#define		HFA384x_RATEBIT_11			((uint16_t)8)

/*--- Just some symbolic names for legibility -------*/
#define		HFA384x_TXCMD_NORECL		((uint16_t)0)
#define		HFA384x_TXCMD_RECL		((uint16_t)1)

/*--- MAC Internal memory constants and macros ------*/
/* masks and macros used to manipulate MAC internal memory addresses. */
/* MAC internal memory addresses are 23 bit quantities.  The MAC uses
 * a paged address space where the upper 16 bits are the page number
 * and the lower 7 bits are the offset.  There are various Host API
 * elements that require two 16-bit quantities to specify a MAC
 * internal memory address.  Unfortunately, some of the API's use a
 * page/offset format where the offset value is JUST the lower seven
 * bits and the page is  the remaining 16 bits.  Some of the API's
 * assume that the 23 bit address has been split at the 16th bit.  We
 * refer to these two formats as AUX format and CMD format.  The
 * macros below help handle some of this.
 */

/* Handy constant */
#define		HFA384x_ADDR_AUX_OFF_MAX	((uint16_t)0x007f)

/* Mask bits for discarding unwanted pieces in a flat address */
#define		HFA384x_ADDR_FLAT_AUX_PAGE_MASK	(0x007fff80)
#define		HFA384x_ADDR_FLAT_AUX_OFF_MASK	(0x0000007f)
#define		HFA384x_ADDR_FLAT_CMD_PAGE_MASK	(0xffff0000)
#define		HFA384x_ADDR_FLAT_CMD_OFF_MASK	(0x0000ffff)

/* Mask bits for discarding unwanted pieces in AUX format 16-bit address parts */
#define		HFA384x_ADDR_AUX_PAGE_MASK	(0xffff)
#define		HFA384x_ADDR_AUX_OFF_MASK	(0x007f)

/* Mask bits for discarding unwanted pieces in CMD format 16-bit address parts */
#define		HFA384x_ADDR_CMD_PAGE_MASK	(0x007f)
#define		HFA384x_ADDR_CMD_OFF_MASK	(0xffff)

/* Make a 32-bit flat address from AUX format 16-bit page and offset */
#define		HFA384x_ADDR_AUX_MKFLAT(p,o)	\
		(((uint32_t)(((uint16_t)(p))&HFA384x_ADDR_AUX_PAGE_MASK)) <<7) | \
		((uint32_t)(((uint16_t)(o))&HFA384x_ADDR_AUX_OFF_MASK))

/* Make a 32-bit flat address from CMD format 16-bit page and offset */
#define		HFA384x_ADDR_CMD_MKFLAT(p,o)	\
		(((uint32_t)(((uint16_t)(p))&HFA384x_ADDR_CMD_PAGE_MASK)) <<16) | \
		((uint32_t)(((uint16_t)(o))&HFA384x_ADDR_CMD_OFF_MASK))

/* Make AUX format offset and page from a 32-bit flat address */
#define		HFA384x_ADDR_AUX_MKPAGE(f) \
		((uint16_t)((((uint32_t)(f))&HFA384x_ADDR_FLAT_AUX_PAGE_MASK)>>7))
#define		HFA384x_ADDR_AUX_MKOFF(f) \
		((uint16_t)(((uint32_t)(f))&HFA384x_ADDR_FLAT_AUX_OFF_MASK))

/* Make CMD format offset and page from a 32-bit flat address */
#define		HFA384x_ADDR_CMD_MKPAGE(f) \
		((uint16_t)((((uint32_t)(f))&HFA384x_ADDR_FLAT_CMD_PAGE_MASK)>>16))
#define		HFA384x_ADDR_CMD_MKOFF(f) \
		((uint16_t)(((uint32_t)(f))&HFA384x_ADDR_FLAT_CMD_OFF_MASK))

/*--- Aux register masks/tests ----------------------*/
/* Some of the upper bits of the AUX offset register are used to */
/*  select address space. */
#define		HFA384x_AUX_CTL_EXTDS	(0x00)
#define		HFA384x_AUX_CTL_NV	(0x01)
#define		HFA384x_AUX_CTL_PHY	(0x02)
#define		HFA384x_AUX_CTL_ICSRAM	(0x03)

/* Make AUX register offset and page values from a flat address */
#define		HFA384x_AUX_MKOFF(f, c) \
	(HFA384x_ADDR_AUX_MKOFF(f) | (((uint16_t)(c))<<12))
#define		HFA384x_AUX_MKPAGE(f)	HFA384x_ADDR_AUX_MKPAGE(f)


/*--- Controller Memory addresses -------------------*/
#define		HFA3842_PDA_BASE	(0x007f0000UL)
#define		HFA3841_PDA_BASE	(0x003f0000UL)
#define		HFA3841_PDA_BOGUS_BASE	(0x00390000UL)

/*--- Driver Download states  -----------------------*/
#define		HFA384x_DLSTATE_DISABLED		0
#define		HFA384x_DLSTATE_RAMENABLED		1
#define		HFA384x_DLSTATE_FLASHENABLED		2
#define		HFA384x_DLSTATE_FLASHWRITTEN		3
#define		HFA384x_DLSTATE_FLASHWRITEPENDING	4
#define		HFA384x_DLSTATE_GENESIS 		5

/*--- Register I/O offsets --------------------------*/
#if ((WLAN_HOSTIF == WLAN_PCMCIA) || (WLAN_HOSTIF == WLAN_PLX))

#define		HFA384x_CMD_OFF			(0x00)
#define		HFA384x_PARAM0_OFF		(0x02)
#define		HFA384x_PARAM1_OFF		(0x04)
#define		HFA384x_PARAM2_OFF		(0x06)
#define		HFA384x_STATUS_OFF		(0x08)
#define		HFA384x_RESP0_OFF		(0x0A)
#define		HFA384x_RESP1_OFF		(0x0C)
#define		HFA384x_RESP2_OFF		(0x0E)
#define		HFA384x_INFOFID_OFF		(0x10)
#define		HFA384x_RXFID_OFF		(0x20)
#define		HFA384x_ALLOCFID_OFF		(0x22)
#define		HFA384x_TXCOMPLFID_OFF		(0x24)
#define		HFA384x_SELECT0_OFF		(0x18)
#define		HFA384x_OFFSET0_OFF		(0x1C)
#define		HFA384x_DATA0_OFF		(0x36)
#define		HFA384x_SELECT1_OFF		(0x1A)
#define		HFA384x_OFFSET1_OFF		(0x1E)
#define		HFA384x_DATA1_OFF		(0x38)
#define		HFA384x_EVSTAT_OFF		(0x30)
#define		HFA384x_INTEN_OFF		(0x32)
#define		HFA384x_EVACK_OFF		(0x34)
#define		HFA384x_CONTROL_OFF		(0x14)
#define		HFA384x_SWSUPPORT0_OFF		(0x28)
#define		HFA384x_SWSUPPORT1_OFF		(0x2A)
#define		HFA384x_SWSUPPORT2_OFF		(0x2C)
#define		HFA384x_AUXPAGE_OFF		(0x3A)
#define		HFA384x_AUXOFFSET_OFF		(0x3C)
#define		HFA384x_AUXDATA_OFF		(0x3E)

#elif (WLAN_HOSTIF == WLAN_PCI || WLAN_HOSTIF == WLAN_USB)

#define		HFA384x_CMD_OFF			(0x00)
#define		HFA384x_PARAM0_OFF		(0x04)
#define		HFA384x_PARAM1_OFF		(0x08)
#define		HFA384x_PARAM2_OFF		(0x0c)
#define		HFA384x_STATUS_OFF		(0x10)
#define		HFA384x_RESP0_OFF		(0x14)
#define		HFA384x_RESP1_OFF		(0x18)
#define		HFA384x_RESP2_OFF		(0x1c)
#define		HFA384x_INFOFID_OFF		(0x20)
#define		HFA384x_RXFID_OFF		(0x40)
#define		HFA384x_ALLOCFID_OFF		(0x44)
#define		HFA384x_TXCOMPLFID_OFF		(0x48)
#define		HFA384x_SELECT0_OFF		(0x30)
#define		HFA384x_OFFSET0_OFF		(0x38)
#define		HFA384x_DATA0_OFF		(0x6c)
#define		HFA384x_SELECT1_OFF		(0x34)
#define		HFA384x_OFFSET1_OFF		(0x3c)
#define		HFA384x_DATA1_OFF		(0x70)
#define		HFA384x_EVSTAT_OFF		(0x60)
#define		HFA384x_INTEN_OFF		(0x64)
#define		HFA384x_EVACK_OFF		(0x68)
#define		HFA384x_CONTROL_OFF		(0x28)
#define		HFA384x_SWSUPPORT0_OFF		(0x50)
#define		HFA384x_SWSUPPORT1_OFF		(0x54)
#define		HFA384x_SWSUPPORT2_OFF		(0x58)
#define		HFA384x_AUXPAGE_OFF		(0x74)
#define		HFA384x_AUXOFFSET_OFF		(0x78)
#define		HFA384x_AUXDATA_OFF		(0x7c)
#define		HFA384x_PCICOR_OFF		(0x4c)
#define		HFA384x_PCIHCR_OFF		(0x5c)
#define		HFA384x_PCI_M0_ADDRH_OFF	(0x80)
#define		HFA384x_PCI_M0_ADDRL_OFF	(0x84)
#define		HFA384x_PCI_M0_LEN_OFF		(0x88)
#define		HFA384x_PCI_M0_CTL_OFF		(0x8c)
#define		HFA384x_PCI_STATUS_OFF		(0x98)
#define		HFA384x_PCI_M1_ADDRH_OFF	(0xa0)
#define		HFA384x_PCI_M1_ADDRL_OFF	(0xa4)
#define		HFA384x_PCI_M1_LEN_OFF		(0xa8)
#define		HFA384x_PCI_M1_CTL_OFF		(0xac)

#endif

/*--- Register Field Masks --------------------------*/
#define		HFA384x_CMD_BUSY		((uint16_t)BIT15)
#define		HFA384x_CMD_AINFO		((uint16_t)(BIT14 | BIT13 | BIT12 | BIT11 | BIT10 | BIT9 | BIT8))
#define		HFA384x_CMD_MACPORT		((uint16_t)(BIT10 | BIT9 | BIT8))
#define		HFA384x_CMD_RECL		((uint16_t)BIT8)
#define		HFA384x_CMD_WRITE		((uint16_t)BIT8)
#define		HFA384x_CMD_PROGMODE		((uint16_t)(BIT9 | BIT8))
#define		HFA384x_CMD_CMDCODE		((uint16_t)(BIT5 | BIT4 | BIT3 | BIT2 | BIT1 | BIT0))

#define		HFA384x_STATUS_RESULT		((uint16_t)(BIT14 | BIT13 | BIT12 | BIT11 | BIT10 | BIT9 | BIT8))
#define		HFA384x_STATUS_CMDCODE		((uint16_t)(BIT5 | BIT4 | BIT3 | BIT2 | BIT1 | BIT0))

#define		HFA384x_OFFSET_BUSY		((uint16_t)BIT15)
#define		HFA384x_OFFSET_ERR		((uint16_t)BIT14)
#define		HFA384x_OFFSET_DATAOFF		((uint16_t)(BIT11 | BIT10 | BIT9 | BIT8 | BIT7 | BIT6 | BIT5 | BIT4 | BIT3 | BIT2 | BIT1))

#define		HFA384x_EVSTAT_TICK		((uint16_t)BIT15)
#define		HFA384x_EVSTAT_WTERR		((uint16_t)BIT14)
#define		HFA384x_EVSTAT_INFDROP		((uint16_t)BIT13)
#define		HFA384x_EVSTAT_INFO		((uint16_t)BIT7)
#define		HFA384x_EVSTAT_DTIM		((uint16_t)BIT5)
#define		HFA384x_EVSTAT_CMD		((uint16_t)BIT4)
#define		HFA384x_EVSTAT_ALLOC		((uint16_t)BIT3)
#define		HFA384x_EVSTAT_TXEXC		((uint16_t)BIT2)
#define		HFA384x_EVSTAT_TX		((uint16_t)BIT1)
#define		HFA384x_EVSTAT_RX		((uint16_t)BIT0)

#define         HFA384x_INT_BAP_OP           (HFA384x_EVSTAT_INFO|HFA384x_EVSTAT_RX|HFA384x_EVSTAT_TX|HFA384x_EVSTAT_TXEXC)

#define         HFA384x_INT_NORMAL           (HFA384x_EVSTAT_INFO|HFA384x_EVSTAT_RX|HFA384x_EVSTAT_TX|HFA384x_EVSTAT_TXEXC|HFA384x_EVSTAT_INFDROP|HFA384x_EVSTAT_ALLOC|HFA384x_EVSTAT_DTIM)

#define		HFA384x_INTEN_TICK		((uint16_t)BIT15)
#define		HFA384x_INTEN_WTERR		((uint16_t)BIT14)
#define		HFA384x_INTEN_INFDROP		((uint16_t)BIT13)
#define		HFA384x_INTEN_INFO		((uint16_t)BIT7)
#define		HFA384x_INTEN_DTIM		((uint16_t)BIT5)
#define		HFA384x_INTEN_CMD		((uint16_t)BIT4)
#define		HFA384x_INTEN_ALLOC		((uint16_t)BIT3)
#define		HFA384x_INTEN_TXEXC		((uint16_t)BIT2)
#define		HFA384x_INTEN_TX		((uint16_t)BIT1)
#define		HFA384x_INTEN_RX		((uint16_t)BIT0)

#define		HFA384x_EVACK_TICK		((uint16_t)BIT15)
#define		HFA384x_EVACK_WTERR		((uint16_t)BIT14)
#define		HFA384x_EVACK_INFDROP		((uint16_t)BIT13)
#define		HFA384x_EVACK_INFO		((uint16_t)BIT7)
#define		HFA384x_EVACK_DTIM		((uint16_t)BIT5)
#define		HFA384x_EVACK_CMD		((uint16_t)BIT4)
#define		HFA384x_EVACK_ALLOC		((uint16_t)BIT3)
#define		HFA384x_EVACK_TXEXC		((uint16_t)BIT2)
#define		HFA384x_EVACK_TX		((uint16_t)BIT1)
#define		HFA384x_EVACK_RX		((uint16_t)BIT0)

#define		HFA384x_CONTROL_AUXEN		((uint16_t)(BIT15 | BIT14))


/*--- Command Code Constants --------------------------*/
/*--- Controller Commands --------------------------*/
#define		HFA384x_CMDCODE_INIT		((uint16_t)0x00)
#define		HFA384x_CMDCODE_ENABLE		((uint16_t)0x01)
#define		HFA384x_CMDCODE_DISABLE		((uint16_t)0x02)
#define		HFA384x_CMDCODE_DIAG		((uint16_t)0x03)

/*--- Buffer Mgmt Commands --------------------------*/
#define		HFA384x_CMDCODE_ALLOC		((uint16_t)0x0A)
#define		HFA384x_CMDCODE_TX		((uint16_t)0x0B)
#define		HFA384x_CMDCODE_CLRPRST		((uint16_t)0x12)

/*--- Regulate Commands --------------------------*/
#define		HFA384x_CMDCODE_NOTIFY		((uint16_t)0x10)
#define		HFA384x_CMDCODE_INQ		((uint16_t)0x11)

/*--- Configure Commands --------------------------*/
#define		HFA384x_CMDCODE_ACCESS		((uint16_t)0x21)
#define		HFA384x_CMDCODE_DOWNLD		((uint16_t)0x22)

/*--- Debugging Commands -----------------------------*/
#define 	HFA384x_CMDCODE_MONITOR		((uint16_t)(0x38))
#define		HFA384x_MONITOR_ENABLE		((uint16_t)(0x0b))
#define		HFA384x_MONITOR_DISABLE		((uint16_t)(0x0f))

/*--- Result Codes --------------------------*/
#define		HFA384x_SUCCESS			((uint16_t)(0x00))
#define		HFA384x_CARD_FAIL		((uint16_t)(0x01))
#define		HFA384x_NO_BUFF			((uint16_t)(0x05))
#define		HFA384x_CMD_ERR			((uint16_t)(0x7F))

/*--- Programming Modes --------------------------
	MODE 0: Disable programming
	MODE 1: Enable volatile memory programming
	MODE 2: Enable non-volatile memory programming
	MODE 3: Program non-volatile memory section
--------------------------------------------------*/
#define		HFA384x_PROGMODE_DISABLE	((uint16_t)0x00)
#define		HFA384x_PROGMODE_RAM		((uint16_t)0x01)
#define		HFA384x_PROGMODE_NV		((uint16_t)0x02)
#define		HFA384x_PROGMODE_NVWRITE	((uint16_t)0x03)

/*--- AUX register enable --------------------------*/
#define		HFA384x_AUXPW0			((uint16_t)0xfe01)
#define		HFA384x_AUXPW1			((uint16_t)0xdc23)
#define		HFA384x_AUXPW2			((uint16_t)0xba45)

#define		HFA384x_CONTROL_AUX_ISDISABLED	((uint16_t)0x0000)
#define		HFA384x_CONTROL_AUX_ISENABLED	((uint16_t)0xc000)
#define		HFA384x_CONTROL_AUX_DOENABLE	((uint16_t)0x8000)
#define		HFA384x_CONTROL_AUX_DODISABLE	((uint16_t)0x4000)

/*--- Record ID Constants --------------------------*/
/*--------------------------------------------------------------------
Configuration RIDs: Network Parameters, Static Configuration Entities
--------------------------------------------------------------------*/
#define		HFA384x_RID_CNFPORTTYPE		((uint16_t)0xFC00)
#define		HFA384x_RID_CNFOWNMACADDR	((uint16_t)0xFC01)
#define		HFA384x_RID_CNFDESIREDSSID	((uint16_t)0xFC02)
#define		HFA384x_RID_CNFOWNCHANNEL	((uint16_t)0xFC03)
#define		HFA384x_RID_CNFOWNSSID		((uint16_t)0xFC04)
#define		HFA384x_RID_CNFOWNATIMWIN	((uint16_t)0xFC05)
#define		HFA384x_RID_CNFSYSSCALE		((uint16_t)0xFC06)
#define		HFA384x_RID_CNFMAXDATALEN	((uint16_t)0xFC07)
#define		HFA384x_RID_CNFWDSADDR		((uint16_t)0xFC08)
#define		HFA384x_RID_CNFPMENABLED	((uint16_t)0xFC09)
#define		HFA384x_RID_CNFPMEPS		((uint16_t)0xFC0A)
#define		HFA384x_RID_CNFMULTICASTRX	((uint16_t)0xFC0B)
#define		HFA384x_RID_CNFMAXSLEEPDUR	((uint16_t)0xFC0C)
#define		HFA384x_RID_CNFPMHOLDDUR	((uint16_t)0xFC0D)
#define		HFA384x_RID_CNFOWNNAME		((uint16_t)0xFC0E)
#define		HFA384x_RID_CNFOWNDTIMPER	((uint16_t)0xFC10)
#define		HFA384x_RID_CNFWDSADDR1		((uint16_t)0xFC11)
#define		HFA384x_RID_CNFWDSADDR2		((uint16_t)0xFC12)
#define		HFA384x_RID_CNFWDSADDR3		((uint16_t)0xFC13)
#define		HFA384x_RID_CNFWDSADDR4		((uint16_t)0xFC14)
#define		HFA384x_RID_CNFWDSADDR5		((uint16_t)0xFC15)
#define		HFA384x_RID_CNFWDSADDR6		((uint16_t)0xFC16)
#define		HFA384x_RID_CNFMCASTPMBUFF	((uint16_t)0xFC17)

/*--------------------------------------------------------------------
Configuration RID lengths: Network Params, Static Config Entities
  This is the length of JUST the DATA part of the RID (does not
  include the len or code fields)
--------------------------------------------------------------------*/
/* TODO: fill in the rest of these */
#define		HFA384x_RID_CNFPORTTYPE_LEN	((uint16_t)2)
#define		HFA384x_RID_CNFOWNMACADDR_LEN	((uint16_t)6)
#define		HFA384x_RID_CNFDESIREDSSID_LEN	((uint16_t)34)
#define		HFA384x_RID_CNFOWNCHANNEL_LEN	((uint16_t)2)
#define		HFA384x_RID_CNFOWNSSID_LEN	((uint16_t)34)
#define		HFA384x_RID_CNFOWNATIMWIN_LEN	((uint16_t)2)
#define		HFA384x_RID_CNFSYSSCALE_LEN	((uint16_t)0)
#define		HFA384x_RID_CNFMAXDATALEN_LEN	((uint16_t)0)
#define		HFA384x_RID_CNFWDSADDR_LEN	((uint16_t)6)
#define		HFA384x_RID_CNFPMENABLED_LEN	((uint16_t)0)
#define		HFA384x_RID_CNFPMEPS_LEN	((uint16_t)0)
#define		HFA384x_RID_CNFMULTICASTRX_LEN	((uint16_t)0)
#define		HFA384x_RID_CNFMAXSLEEPDUR_LEN	((uint16_t)0)
#define		HFA384x_RID_CNFPMHOLDDUR_LEN	((uint16_t)0)
#define		HFA384x_RID_CNFOWNNAME_LEN	((uint16_t)34)
#define		HFA384x_RID_CNFOWNDTIMPER_LEN	((uint16_t)0)
#define		HFA384x_RID_CNFWDSADDR1_LEN	((uint16_t)6)
#define		HFA384x_RID_CNFWDSADDR2_LEN	((uint16_t)6)
#define		HFA384x_RID_CNFWDSADDR3_LEN	((uint16_t)6)
#define		HFA384x_RID_CNFWDSADDR4_LEN	((uint16_t)6)
#define		HFA384x_RID_CNFWDSADDR5_LEN	((uint16_t)6)
#define		HFA384x_RID_CNFWDSADDR6_LEN	((uint16_t)6)
#define		HFA384x_RID_CNFMCASTPMBUFF_LEN	((uint16_t)0)
#define		HFA384x_RID_CNFAUTHENTICATION_LEN ((uint16_t)sizeof(uint16_t))
#define		HFA384x_RID_CNFMAXSLEEPDUR_LEN	((uint16_t)0)

/*--------------------------------------------------------------------
Configuration RIDs: Network Parameters, Dynamic Configuration Entities
--------------------------------------------------------------------*/
#define		HFA384x_RID_GROUPADDR		((uint16_t)0xFC80)
#define		HFA384x_RID_CREATEIBSS		((uint16_t)0xFC81)
#define		HFA384x_RID_FRAGTHRESH		((uint16_t)0xFC82)
#define		HFA384x_RID_RTSTHRESH		((uint16_t)0xFC83)
#define		HFA384x_RID_TXRATECNTL		((uint16_t)0xFC84)
#define		HFA384x_RID_PROMISCMODE		((uint16_t)0xFC85)
#define		HFA384x_RID_FRAGTHRESH0		((uint16_t)0xFC90)
#define		HFA384x_RID_FRAGTHRESH1		((uint16_t)0xFC91)
#define		HFA384x_RID_FRAGTHRESH2		((uint16_t)0xFC92)
#define		HFA384x_RID_FRAGTHRESH3		((uint16_t)0xFC93)
#define		HFA384x_RID_FRAGTHRESH4		((uint16_t)0xFC94)
#define		HFA384x_RID_FRAGTHRESH5		((uint16_t)0xFC95)
#define		HFA384x_RID_FRAGTHRESH6		((uint16_t)0xFC96)
#define		HFA384x_RID_RTSTHRESH0		((uint16_t)0xFC97)
#define		HFA384x_RID_RTSTHRESH1		((uint16_t)0xFC98)
#define		HFA384x_RID_RTSTHRESH2		((uint16_t)0xFC99)
#define		HFA384x_RID_RTSTHRESH3		((uint16_t)0xFC9A)
#define		HFA384x_RID_RTSTHRESH4		((uint16_t)0xFC9B)
#define		HFA384x_RID_RTSTHRESH5		((uint16_t)0xFC9C)
#define		HFA384x_RID_RTSTHRESH6		((uint16_t)0xFC9D)
#define		HFA384x_RID_TXRATECNTL0		((uint16_t)0xFC9E)
#define		HFA384x_RID_TXRATECNTL1		((uint16_t)0xFC9F)
#define		HFA384x_RID_TXRATECNTL2		((uint16_t)0xFCA0)
#define		HFA384x_RID_TXRATECNTL3		((uint16_t)0xFCA1)
#define		HFA384x_RID_TXRATECNTL4		((uint16_t)0xFCA2)
#define		HFA384x_RID_TXRATECNTL5		((uint16_t)0xFCA3)
#define		HFA384x_RID_TXRATECNTL6		((uint16_t)0xFCA4)

/*--------------------------------------------------------------------
Configuration RID Lengths: Network Param, Dynamic Config Entities
  This is the length of JUST the DATA part of the RID (does not
  include the len or code fields)
--------------------------------------------------------------------*/
/* TODO: fill in the rest of these */
#define		HFA384x_RID_GROUPADDR_LEN	((uint16_t)16 * WLAN_ADDR_LEN)
#define		HFA384x_RID_CREATEIBSS_LEN	((uint16_t)0)
#define		HFA384x_RID_FRAGTHRESH_LEN	((uint16_t)0)
#define		HFA384x_RID_RTSTHRESH_LEN	((uint16_t)0)
#define		HFA384x_RID_TXRATECNTL_LEN	((uint16_t)4)
#define		HFA384x_RID_PROMISCMODE_LEN	((uint16_t)2)
#define		HFA384x_RID_FRAGTHRESH0_LEN	((uint16_t)0)
#define		HFA384x_RID_FRAGTHRESH1_LEN	((uint16_t)0)
#define		HFA384x_RID_FRAGTHRESH2_LEN	((uint16_t)0)
#define		HFA384x_RID_FRAGTHRESH3_LEN	((uint16_t)0)
#define		HFA384x_RID_FRAGTHRESH4_LEN	((uint16_t)0)
#define		HFA384x_RID_FRAGTHRESH5_LEN	((uint16_t)0)
#define		HFA384x_RID_FRAGTHRESH6_LEN	((uint16_t)0)
#define		HFA384x_RID_RTSTHRESH0_LEN	((uint16_t)0)
#define		HFA384x_RID_RTSTHRESH1_LEN	((uint16_t)0)
#define		HFA384x_RID_RTSTHRESH2_LEN	((uint16_t)0)
#define		HFA384x_RID_RTSTHRESH3_LEN	((uint16_t)0)
#define		HFA384x_RID_RTSTHRESH4_LEN	((uint16_t)0)
#define		HFA384x_RID_RTSTHRESH5_LEN	((uint16_t)0)
#define		HFA384x_RID_RTSTHRESH6_LEN	((uint16_t)0)
#define		HFA384x_RID_TXRATECNTL0_LEN	((uint16_t)0)
#define		HFA384x_RID_TXRATECNTL1_LEN	((uint16_t)0)
#define		HFA384x_RID_TXRATECNTL2_LEN	((uint16_t)0)
#define		HFA384x_RID_TXRATECNTL3_LEN	((uint16_t)0)
#define		HFA384x_RID_TXRATECNTL4_LEN	((uint16_t)0)
#define		HFA384x_RID_TXRATECNTL5_LEN	((uint16_t)0)
#define		HFA384x_RID_TXRATECNTL6_LEN	((uint16_t)0)

/*--------------------------------------------------------------------
Configuration RIDs: Behavior Parameters
--------------------------------------------------------------------*/
#define		HFA384x_RID_ITICKTIME		((uint16_t)0xFCE0)

/*--------------------------------------------------------------------
Configuration RID Lengths: Behavior Parameters
  This is the length of JUST the DATA part of the RID (does not
  include the len or code fields)
--------------------------------------------------------------------*/
#define		HFA384x_RID_ITICKTIME_LEN	((uint16_t)2)

/*----------------------------------------------------------------------
Information RIDs: NIC Information
--------------------------------------------------------------------*/
#define		HFA384x_RID_MAXLOADTIME		((uint16_t)0xFD00)
#define		HFA384x_RID_DOWNLOADBUFFER	((uint16_t)0xFD01)
#define		HFA384x_RID_PRIIDENTITY		((uint16_t)0xFD02)
#define		HFA384x_RID_PRISUPRANGE		((uint16_t)0xFD03)
#define		HFA384x_RID_PRI_CFIACTRANGES	((uint16_t)0xFD04)
#define		HFA384x_RID_NICSERIALNUMBER	((uint16_t)0xFD0A)
#define		HFA384x_RID_NICIDENTITY		((uint16_t)0xFD0B)
#define		HFA384x_RID_MFISUPRANGE		((uint16_t)0xFD0C)
#define		HFA384x_RID_CFISUPRANGE		((uint16_t)0xFD0D)
#define		HFA384x_RID_CHANNELLIST		((uint16_t)0xFD10)
#define		HFA384x_RID_REGULATORYDOMAINS	((uint16_t)0xFD11)
#define		HFA384x_RID_TEMPTYPE		((uint16_t)0xFD12)
#define		HFA384x_RID_CIS			((uint16_t)0xFD13)
#define		HFA384x_RID_STAIDENTITY		((uint16_t)0xFD20)
#define		HFA384x_RID_STASUPRANGE		((uint16_t)0xFD21)
#define		HFA384x_RID_STA_MFIACTRANGES	((uint16_t)0xFD22)
#define		HFA384x_RID_STA_CFIACTRANGES	((uint16_t)0xFD23)
#define		HFA384x_RID_BUILDSEQ		((uint16_t)0xFFFE)
#define		HFA384x_RID_FWID		((uint16_t)0xFFFF)

/*----------------------------------------------------------------------
Information RID Lengths: NIC Information
  This is the length of JUST the DATA part of the RID (does not
  include the len or code fields)
--------------------------------------------------------------------*/
#define		HFA384x_RID_MAXLOADTIME_LEN		((uint16_t)0)
#define		HFA384x_RID_DOWNLOADBUFFER_LEN		((uint16_t)sizeof(hfa384x_downloadbuffer_t))
#define		HFA384x_RID_PRIIDENTITY_LEN		((uint16_t)8)
#define		HFA384x_RID_PRISUPRANGE_LEN		((uint16_t)10)
#define		HFA384x_RID_CFIACTRANGES_LEN		((uint16_t)10)
#define		HFA384x_RID_NICSERIALNUMBER_LEN		((uint16_t)12)
#define		HFA384x_RID_NICIDENTITY_LEN		((uint16_t)8)
#define		HFA384x_RID_MFISUPRANGE_LEN		((uint16_t)10)
#define		HFA384x_RID_CFISUPRANGE_LEN		((uint16_t)10)
#define		HFA384x_RID_CHANNELLIST_LEN		((uint16_t)0)
#define		HFA384x_RID_REGULATORYDOMAINS_LEN	((uint16_t)12)
#define		HFA384x_RID_TEMPTYPE_LEN		((uint16_t)0)
#define		HFA384x_RID_CIS_LEN			((uint16_t)480)
#define		HFA384x_RID_STAIDENTITY_LEN		((uint16_t)8)
#define		HFA384x_RID_STASUPRANGE_LEN		((uint16_t)10)
#define		HFA384x_RID_MFIACTRANGES_LEN		((uint16_t)10)
#define		HFA384x_RID_CFIACTRANGES2_LEN		((uint16_t)10)
#define		HFA384x_RID_BUILDSEQ_LEN		((uint16_t)sizeof(hfa384x_BuildSeq_t))
#define		HFA384x_RID_FWID_LEN			((uint16_t)sizeof(hfa384x_FWID_t))

/*--------------------------------------------------------------------
Information RIDs:  MAC Information
--------------------------------------------------------------------*/
#define		HFA384x_RID_PORTSTATUS		((uint16_t)0xFD40)
#define		HFA384x_RID_CURRENTSSID		((uint16_t)0xFD41)
#define		HFA384x_RID_CURRENTBSSID	((uint16_t)0xFD42)
#define		HFA384x_RID_COMMSQUALITY	((uint16_t)0xFD43)
#define		HFA384x_RID_CURRENTTXRATE	((uint16_t)0xFD44)
#define		HFA384x_RID_CURRENTBCNint	((uint16_t)0xFD45)
#define		HFA384x_RID_CURRENTSCALETHRESH	((uint16_t)0xFD46)
#define		HFA384x_RID_PROTOCOLRSPTIME	((uint16_t)0xFD47)
#define		HFA384x_RID_SHORTRETRYLIMIT	((uint16_t)0xFD48)
#define		HFA384x_RID_LONGRETRYLIMIT	((uint16_t)0xFD49)
#define		HFA384x_RID_MAXTXLIFETIME	((uint16_t)0xFD4A)
#define		HFA384x_RID_MAXRXLIFETIME	((uint16_t)0xFD4B)
#define		HFA384x_RID_CFPOLLABLE		((uint16_t)0xFD4C)
#define		HFA384x_RID_AUTHALGORITHMS	((uint16_t)0xFD4D)
#define		HFA384x_RID_PRIVACYOPTIMP	((uint16_t)0xFD4F)
#define		HFA384x_RID_DBMCOMMSQUALITY	((uint16_t)0xFD51)
#define		HFA384x_RID_CURRENTTXRATE1	((uint16_t)0xFD80)
#define		HFA384x_RID_CURRENTTXRATE2	((uint16_t)0xFD81)
#define		HFA384x_RID_CURRENTTXRATE3	((uint16_t)0xFD82)
#define		HFA384x_RID_CURRENTTXRATE4	((uint16_t)0xFD83)
#define		HFA384x_RID_CURRENTTXRATE5	((uint16_t)0xFD84)
#define		HFA384x_RID_CURRENTTXRATE6	((uint16_t)0xFD85)
#define		HFA384x_RID_OWNMACADDRESS	((uint16_t)0xFD86)
// #define	HFA384x_RID_PCFINFO		((uint16_t)0xFD87)
#define		HFA384x_RID_SCANRESULTS       	((uint16_t)0xFD88) // NEW
#define		HFA384x_RID_HOSTSCANRESULTS   	((uint16_t)0xFD89) // NEW
#define		HFA384x_RID_AUTHENTICATIONUSED	((uint16_t)0xFD8A) // NEW
#define		HFA384x_RID_ASSOCIATEFAILURE  	((uint16_t)0xFD8D) // 1.8.0

/*--------------------------------------------------------------------
Information RID Lengths:  MAC Information
  This is the length of JUST the DATA part of the RID (does not
  include the len or code fields)
--------------------------------------------------------------------*/
#define		HFA384x_RID_PORTSTATUS_LEN		((uint16_t)0)
#define		HFA384x_RID_CURRENTSSID_LEN		((uint16_t)34)
#define		HFA384x_RID_CURRENTBSSID_LEN		((uint16_t)WLAN_BSSID_LEN)
#define		HFA384x_RID_COMMSQUALITY_LEN		((uint16_t)sizeof(hfa384x_commsquality_t))
#define		HFA384x_RID_DBMCOMMSQUALITY_LEN		((uint16_t)sizeof(hfa384x_dbmcommsquality_t))
#define		HFA384x_RID_CURRENTTXRATE_LEN		((uint16_t)0)
#define		HFA384x_RID_CURRENTBCNINT_LEN		((uint16_t)0)
#define		HFA384x_RID_STACURSCALETHRESH_LEN	((uint16_t)12)
#define		HFA384x_RID_APCURSCALETHRESH_LEN	((uint16_t)6)
#define		HFA384x_RID_PROTOCOLRSPTIME_LEN		((uint16_t)0)
#define		HFA384x_RID_SHORTRETRYLIMIT_LEN		((uint16_t)0)
#define		HFA384x_RID_LONGRETRYLIMIT_LEN		((uint16_t)0)
#define		HFA384x_RID_MAXTXLIFETIME_LEN		((uint16_t)0)
#define		HFA384x_RID_MAXRXLIFETIME_LEN		((uint16_t)0)
#define		HFA384x_RID_CFPOLLABLE_LEN		((uint16_t)0)
#define		HFA384x_RID_AUTHALGORITHMS_LEN		((uint16_t)4)
#define		HFA384x_RID_PRIVACYOPTIMP_LEN		((uint16_t)0)
#define		HFA384x_RID_CURRENTTXRATE1_LEN		((uint16_t)0)
#define		HFA384x_RID_CURRENTTXRATE2_LEN		((uint16_t)0)
#define		HFA384x_RID_CURRENTTXRATE3_LEN		((uint16_t)0)
#define		HFA384x_RID_CURRENTTXRATE4_LEN		((uint16_t)0)
#define		HFA384x_RID_CURRENTTXRATE5_LEN		((uint16_t)0)
#define		HFA384x_RID_CURRENTTXRATE6_LEN		((uint16_t)0)
#define		HFA384x_RID_OWNMACADDRESS_LEN		((uint16_t)6)
#define		HFA384x_RID_PCFINFO_LEN			((uint16_t)6)
#define		HFA384x_RID_CNFAPPCFINFO_LEN		((uint16_t)sizeof(hfa384x_PCFInfo_data_t))
#define		HFA384x_RID_SCANREQUEST_LEN		((uint16_t)sizeof(hfa384x_ScanRequest_data_t))
#define		HFA384x_RID_JOINREQUEST_LEN		((uint16_t)sizeof(hfa384x_JoinRequest_data_t))
#define		HFA384x_RID_AUTHENTICATESTA_LEN		((uint16_t)sizeof(hfa384x_authenticateStation_data_t))
#define		HFA384x_RID_CHANNELINFOREQUEST_LEN	((uint16_t)sizeof(hfa384x_ChannelInfoRequest_data_t))
/*--------------------------------------------------------------------
Information RIDs:  Modem Information
--------------------------------------------------------------------*/
#define		HFA384x_RID_PHYTYPE		((uint16_t)0xFDC0)
#define		HFA384x_RID_CURRENTCHANNEL	((uint16_t)0xFDC1)
#define		HFA384x_RID_CURRENTPOWERSTATE	((uint16_t)0xFDC2)
#define		HFA384x_RID_CCAMODE		((uint16_t)0xFDC3)
#define		HFA384x_RID_SUPPORTEDDATARATES	((uint16_t)0xFDC6)
#define		HFA384x_RID_LFOSTATUS           ((uint16_t)0xFDC7) // 1.7.1

/*--------------------------------------------------------------------
Information RID Lengths:  Modem Information
  This is the length of JUST the DATA part of the RID (does not
  include the len or code fields)
--------------------------------------------------------------------*/
#define		HFA384x_RID_PHYTYPE_LEN			((uint16_t)0)
#define		HFA384x_RID_CURRENTCHANNEL_LEN		((uint16_t)0)
#define		HFA384x_RID_CURRENTPOWERSTATE_LEN	((uint16_t)0)
#define		HFA384x_RID_CCAMODE_LEN			((uint16_t)0)
#define		HFA384x_RID_SUPPORTEDDATARATES_LEN	((uint16_t)10)

/*--------------------------------------------------------------------
API ENHANCEMENTS (NOT ALREADY IMPLEMENTED)
--------------------------------------------------------------------*/
#define		HFA384x_RID_CNFWEPDEFAULTKEYID	((uint16_t)0xFC23)
#define		HFA384x_RID_CNFWEPDEFAULTKEY0	((uint16_t)0xFC24)
#define		HFA384x_RID_CNFWEPDEFAULTKEY1	((uint16_t)0xFC25)
#define		HFA384x_RID_CNFWEPDEFAULTKEY2	((uint16_t)0xFC26)
#define		HFA384x_RID_CNFWEPDEFAULTKEY3	((uint16_t)0xFC27)
#define		HFA384x_RID_CNFWEPFLAGS		((uint16_t)0xFC28)
#define		HFA384x_RID_CNFWEPKEYMAPTABLE	((uint16_t)0xFC29)
#define		HFA384x_RID_CNFAUTHENTICATION	((uint16_t)0xFC2A)
#define		HFA384x_RID_CNFMAXASSOCSTATIONS	((uint16_t)0xFC2B)
#define		HFA384x_RID_CNFTXCONTROL	((uint16_t)0xFC2C)
#define		HFA384x_RID_CNFROAMINGMODE	((uint16_t)0xFC2D)
#define		HFA384x_RID_CNFHOSTAUTHASSOC	((uint16_t)0xFC2E)
#define		HFA384x_RID_CNFRCVCRCERROR	((uint16_t)0xFC30)
// #define		HFA384x_RID_CNFMMLIFE		((uint16_t)0xFC31)
#define		HFA384x_RID_CNFALTRETRYCNT	((uint16_t)0xFC32)
#define		HFA384x_RID_CNFAPBCNint		((uint16_t)0xFC33)
#define		HFA384x_RID_CNFAPPCFINFO	((uint16_t)0xFC34)
#define		HFA384x_RID_CNFSTAPCFINFO	((uint16_t)0xFC35)
#define		HFA384x_RID_CNFPRIORITYQUSAGE	((uint16_t)0xFC37)
#define		HFA384x_RID_CNFTIMCTRL		((uint16_t)0xFC40)
#define		HFA384x_RID_CNFTHIRTY2TALLY	((uint16_t)0xFC42)
#define		HFA384x_RID_CNFENHSECURITY	((uint16_t)0xFC43)
#define		HFA384x_RID_CNFDBMADJUST  	((uint16_t)0xFC46) // NEW
#define		HFA384x_RID_CNFWPADATA       	((uint16_t)0xFC48) // 1.7.0
#define		HFA384x_RID_CNFPROPOGATIONDELAY	((uint16_t)0xFC49) // 1.7.6
#define		HFA384x_RID_CNFSHORTPREAMBLE	((uint16_t)0xFCB0)
#define		HFA384x_RID_CNFEXCLONGPREAMBLE	((uint16_t)0xFCB1)
#define		HFA384x_RID_CNFAUTHRSPTIMEOUT	((uint16_t)0xFCB2)
#define		HFA384x_RID_CNFBASICRATES	((uint16_t)0xFCB3)
#define		HFA384x_RID_CNFSUPPRATES	((uint16_t)0xFCB4)
#define		HFA384x_RID_CNFFALLBACKCTRL	((uint16_t)0xFCB5) // NEW
#define		HFA384x_RID_WEPKEYSTATUS   	((uint16_t)0xFCB6) // NEW
#define		HFA384x_RID_WEPKEYMAPINDEX 	((uint16_t)0xFCB7) // NEW
#define		HFA384x_RID_BROADCASTKEYID 	((uint16_t)0xFCB8) // NEW
#define		HFA384x_RID_ENTSECFLAGEYID 	((uint16_t)0xFCB9) // NEW
#define		HFA384x_RID_CNFPASSIVESCANCTRL	((uint16_t)0xFCBA) // NEW STA
#define		HFA384x_RID_CNFWPAHANDLING	((uint16_t)0xFCBB) // 1.7.0
#define		HFA384x_RID_MDCCONTROL        	((uint16_t)0xFCBC) // 1.7.0/1.4.0
#define		HFA384x_RID_MDCCOUNTRY        	((uint16_t)0xFCBD) // 1.7.0/1.4.0
#define		HFA384x_RID_TXPOWERMAX        	((uint16_t)0xFCBE) // 1.7.0/1.4.0
#define		HFA384x_RID_CNFLFOENBLED      	((uint16_t)0xFCBF) // 1.6.3
#define         HFA384x_RID_CAPINFO             ((uint16_t)0xFCC0) // 1.7.0/1.3.7
#define         HFA384x_RID_LISTENINTERVAL      ((uint16_t)0xFCC1) // 1.7.0/1.3.7
#define         HFA384x_RID_DIVERSITYENABLED    ((uint16_t)0xFCC2) // 1.7.0/1.3.7
#define         HFA384x_RID_LED_CONTROL         ((uint16_t)0xFCC4) // 1.7.6
#define         HFA384x_RID_HFO_DELAY           ((uint16_t)0xFCC5) // 1.7.6
#define         HFA384x_RID_DISSALOWEDBSSID     ((uint16_t)0xFCC6) // 1.8.0
#define		HFA384x_RID_SCANREQUEST		((uint16_t)0xFCE1)
#define		HFA384x_RID_JOINREQUEST		((uint16_t)0xFCE2)
#define		HFA384x_RID_AUTHENTICATESTA	((uint16_t)0xFCE3)
#define		HFA384x_RID_CHANNELINFOREQUEST	((uint16_t)0xFCE4)
#define		HFA384x_RID_HOSTSCAN          	((uint16_t)0xFCE5) // NEW STA
#define		HFA384x_RID_ASSOCIATESTA	((uint16_t)0xFCE6)

#define		HFA384x_RID_CNFWEPDEFAULTKEY_LEN	((uint16_t)6)
#define		HFA384x_RID_CNFWEP128DEFAULTKEY_LEN	((uint16_t)14)
#define		HFA384x_RID_CNFPRIOQUSAGE_LEN		((uint16_t)4)
/*--------------------------------------------------------------------
PD Record codes
--------------------------------------------------------------------*/
#define HFA384x_PDR_PCB_PARTNUM		((uint16_t)0x0001)
#define HFA384x_PDR_PDAVER		((uint16_t)0x0002)
#define HFA384x_PDR_NIC_SERIAL		((uint16_t)0x0003)
#define HFA384x_PDR_MKK_MEASUREMENTS	((uint16_t)0x0004)
#define HFA384x_PDR_NIC_RAMSIZE		((uint16_t)0x0005)
#define HFA384x_PDR_MFISUPRANGE		((uint16_t)0x0006)
#define HFA384x_PDR_CFISUPRANGE		((uint16_t)0x0007)
#define HFA384x_PDR_NICID		((uint16_t)0x0008)
//#define HFA384x_PDR_REFDAC_MEASUREMENTS	((uint16_t)0x0010)
//#define HFA384x_PDR_VGDAC_MEASUREMENTS	((uint16_t)0x0020)
//#define HFA384x_PDR_LEVEL_COMP_MEASUREMENTS	((uint16_t)0x0030)
//#define HFA384x_PDR_MODEM_TRIMDAC_MEASUREMENTS	((uint16_t)0x0040)
//#define HFA384x_PDR_COREGA_HACK		((uint16_t)0x00ff)
#define HFA384x_PDR_MAC_ADDRESS		((uint16_t)0x0101)
//#define HFA384x_PDR_MKK_CALLNAME	((uint16_t)0x0102)
#define HFA384x_PDR_REGDOMAIN		((uint16_t)0x0103)
#define HFA384x_PDR_ALLOWED_CHANNEL	((uint16_t)0x0104)
#define HFA384x_PDR_DEFAULT_CHANNEL	((uint16_t)0x0105)
//#define HFA384x_PDR_PRIVACY_OPTION	((uint16_t)0x0106)
#define HFA384x_PDR_TEMPTYPE		((uint16_t)0x0107)
//#define HFA384x_PDR_REFDAC_SETUP	((uint16_t)0x0110)
//#define HFA384x_PDR_VGDAC_SETUP		((uint16_t)0x0120)
//#define HFA384x_PDR_LEVEL_COMP_SETUP	((uint16_t)0x0130)
//#define HFA384x_PDR_TRIMDAC_SETUP	((uint16_t)0x0140)
#define HFA384x_PDR_IFR_SETTING		((uint16_t)0x0200)
#define HFA384x_PDR_RFR_SETTING		((uint16_t)0x0201)
#define HFA384x_PDR_HFA3861_BASELINE	((uint16_t)0x0202)
#define HFA384x_PDR_HFA3861_SHADOW	((uint16_t)0x0203)
#define HFA384x_PDR_HFA3861_IFRF	((uint16_t)0x0204)
#define HFA384x_PDR_HFA3861_CHCALSP	((uint16_t)0x0300)
#define HFA384x_PDR_HFA3861_CHCALI	((uint16_t)0x0301)
#define HFA384x_PDR_MAX_TX_POWER  	((uint16_t)0x0302)
#define HFA384x_PDR_MASTER_CHAN_LIST	((uint16_t)0x0303)
#define HFA384x_PDR_3842_NIC_CONFIG	((uint16_t)0x0400)
#define HFA384x_PDR_USB_ID		((uint16_t)0x0401)
#define HFA384x_PDR_PCI_ID		((uint16_t)0x0402)
#define HFA384x_PDR_PCI_IFCONF		((uint16_t)0x0403)
#define HFA384x_PDR_PCI_PMCONF		((uint16_t)0x0404)
#define HFA384x_PDR_RFENRGY		((uint16_t)0x0406)
#define HFA384x_PDR_USB_POWER_TYPE      ((uint16_t)0x0407)
//#define HFA384x_PDR_UNKNOWN408		((uint16_t)0x0408)
#define HFA384x_PDR_USB_MAX_POWER	((uint16_t)0x0409)
#define HFA384x_PDR_USB_MANUFACTURER	((uint16_t)0x0410)
#define HFA384x_PDR_USB_PRODUCT  	((uint16_t)0x0411)
#define HFA384x_PDR_ANT_DIVERSITY   	((uint16_t)0x0412)
#define HFA384x_PDR_HFO_DELAY       	((uint16_t)0x0413)
#define HFA384x_PDR_SCALE_THRESH 	((uint16_t)0x0414)

#define HFA384x_PDR_HFA3861_MANF_TESTSP	((uint16_t)0x0900)
#define HFA384x_PDR_HFA3861_MANF_TESTI	((uint16_t)0x0901)
#define HFA384x_PDR_END_OF_PDA		((uint16_t)0x0000)


/*=============================================================*/
/*------ Macros -----------------------------------------------*/

/*--- Register ID macros ------------------------*/

#define		HFA384x_CMD		HFA384x_CMD_OFF
#define		HFA384x_PARAM0		HFA384x_PARAM0_OFF
#define		HFA384x_PARAM1		HFA384x_PARAM1_OFF
#define		HFA384x_PARAM2		HFA384x_PARAM2_OFF
#define		HFA384x_STATUS		HFA384x_STATUS_OFF
#define		HFA384x_RESP0		HFA384x_RESP0_OFF
#define		HFA384x_RESP1		HFA384x_RESP1_OFF
#define		HFA384x_RESP2		HFA384x_RESP2_OFF
#define		HFA384x_INFOFID		HFA384x_INFOFID_OFF
#define		HFA384x_RXFID		HFA384x_RXFID_OFF
#define		HFA384x_ALLOCFID	HFA384x_ALLOCFID_OFF
#define		HFA384x_TXCOMPLFID	HFA384x_TXCOMPLFID_OFF
#define		HFA384x_SELECT0		HFA384x_SELECT0_OFF
#define		HFA384x_OFFSET0		HFA384x_OFFSET0_OFF
#define		HFA384x_DATA0		HFA384x_DATA0_OFF
#define		HFA384x_SELECT1		HFA384x_SELECT1_OFF
#define		HFA384x_OFFSET1		HFA384x_OFFSET1_OFF
#define		HFA384x_DATA1		HFA384x_DATA1_OFF
#define		HFA384x_EVSTAT		HFA384x_EVSTAT_OFF
#define		HFA384x_INTEN		HFA384x_INTEN_OFF
#define		HFA384x_EVACK		HFA384x_EVACK_OFF
#define		HFA384x_CONTROL		HFA384x_CONTROL_OFF
#define		HFA384x_SWSUPPORT0	HFA384x_SWSUPPORT0_OFF
#define		HFA384x_SWSUPPORT1	HFA384x_SWSUPPORT1_OFF
#define		HFA384x_SWSUPPORT2	HFA384x_SWSUPPORT2_OFF
#define		HFA384x_AUXPAGE		HFA384x_AUXPAGE_OFF
#define		HFA384x_AUXOFFSET	HFA384x_AUXOFFSET_OFF
#define		HFA384x_AUXDATA		HFA384x_AUXDATA_OFF
#define		HFA384x_PCICOR		HFA384x_PCICOR_OFF
#define		HFA384x_PCIHCR		HFA384x_PCIHCR_OFF


/*--- Register Test/Get/Set Field macros ------------------------*/

#define		HFA384x_CMD_ISBUSY(value)		((uint16_t)(((uint16_t)value) & HFA384x_CMD_BUSY))
#define		HFA384x_CMD_AINFO_GET(value)		((uint16_t)(((uint16_t)(value) & HFA384x_CMD_AINFO) >> 8))
#define		HFA384x_CMD_AINFO_SET(value)		((uint16_t)((uint16_t)(value) << 8))
#define		HFA384x_CMD_MACPORT_GET(value)		((uint16_t)(HFA384x_CMD_AINFO_GET((uint16_t)(value) & HFA384x_CMD_MACPORT)))
#define		HFA384x_CMD_MACPORT_SET(value)		((uint16_t)HFA384x_CMD_AINFO_SET(value))
#define		HFA384x_CMD_ISRECL(value)		((uint16_t)(HFA384x_CMD_AINFO_GET((uint16_t)(value) & HFA384x_CMD_RECL)))
#define		HFA384x_CMD_RECL_SET(value)		((uint16_t)HFA384x_CMD_AINFO_SET(value))
#define		HFA384x_CMD_QOS_GET(value)		((uint16_t((((uint16_t)(value))&((uint16_t)0x3000)) >> 12))
#define		HFA384x_CMD_QOS_SET(value)		((uint16_t)((((uint16_t)(value)) << 12) & 0x3000))
#define		HFA384x_CMD_ISWRITE(value)		((uint16_t)(HFA384x_CMD_AINFO_GET((uint16_t)(value) & HFA384x_CMD_WRITE)))
#define		HFA384x_CMD_WRITE_SET(value)		((uint16_t)HFA384x_CMD_AINFO_SET((uint16_t)value))
#define		HFA384x_CMD_PROGMODE_GET(value)		((uint16_t)(HFA384x_CMD_AINFO_GET((uint16_t)(value) & HFA384x_CMD_PROGMODE)))
#define		HFA384x_CMD_PROGMODE_SET(value)		((uint16_t)HFA384x_CMD_AINFO_SET((uint16_t)value))
#define		HFA384x_CMD_CMDCODE_GET(value)		((uint16_t)(((uint16_t)(value)) & HFA384x_CMD_CMDCODE))
#define		HFA384x_CMD_CMDCODE_SET(value)		((uint16_t)(value))

#define		HFA384x_STATUS_RESULT_GET(value)	((uint16_t)((((uint16_t)(value)) & HFA384x_STATUS_RESULT) >> 8))
#define		HFA384x_STATUS_RESULT_SET(value)	(((uint16_t)(value)) << 8)
#define		HFA384x_STATUS_CMDCODE_GET(value)	(((uint16_t)(value)) & HFA384x_STATUS_CMDCODE)
#define		HFA384x_STATUS_CMDCODE_SET(value)	((uint16_t)(value))

#define		HFA384x_OFFSET_ISBUSY(value)		((uint16_t)(((uint16_t)(value)) & HFA384x_OFFSET_BUSY))
#define		HFA384x_OFFSET_ISERR(value)		((uint16_t)(((uint16_t)(value)) & HFA384x_OFFSET_ERR))
#define		HFA384x_OFFSET_DATAOFF_GET(value)	((uint16_t)(((uint16_t)(value)) & HFA384x_OFFSET_DATAOFF))
#define		HFA384x_OFFSET_DATAOFF_SET(value)	((uint16_t)(value))

#define		HFA384x_EVSTAT_ISTICK(value)		((uint16_t)(((uint16_t)(value)) & HFA384x_EVSTAT_TICK))
#define		HFA384x_EVSTAT_ISWTERR(value)		((uint16_t)(((uint16_t)(value)) & HFA384x_EVSTAT_WTERR))
#define		HFA384x_EVSTAT_ISINFDROP(value)		((uint16_t)(((uint16_t)(value)) & HFA384x_EVSTAT_INFDROP))
#define		HFA384x_EVSTAT_ISINFO(value)		((uint16_t)(((uint16_t)(value)) & HFA384x_EVSTAT_INFO))
#define		HFA384x_EVSTAT_ISDTIM(value)		((uint16_t)(((uint16_t)(value)) & HFA384x_EVSTAT_DTIM))
#define		HFA384x_EVSTAT_ISCMD(value)		((uint16_t)(((uint16_t)(value)) & HFA384x_EVSTAT_CMD))
#define		HFA384x_EVSTAT_ISALLOC(value)		((uint16_t)(((uint16_t)(value)) & HFA384x_EVSTAT_ALLOC))
#define		HFA384x_EVSTAT_ISTXEXC(value)		((uint16_t)(((uint16_t)(value)) & HFA384x_EVSTAT_TXEXC))
#define		HFA384x_EVSTAT_ISTX(value)		((uint16_t)(((uint16_t)(value)) & HFA384x_EVSTAT_TX))
#define		HFA384x_EVSTAT_ISRX(value)		((uint16_t)(((uint16_t)(value)) & HFA384x_EVSTAT_RX))

#define		HFA384x_EVSTAT_ISBAP_OP(value)		((uint16_t)(((uint16_t)(value)) & HFA384x_INT_BAP_OP))

#define		HFA384x_INTEN_ISTICK(value)		((uint16_t)(((uint16_t)(value)) & HFA384x_INTEN_TICK))
#define		HFA384x_INTEN_TICK_SET(value)		((uint16_t)(((uint16_t)(value)) << 15))
#define		HFA384x_INTEN_ISWTERR(value)		((uint16_t)(((uint16_t)(value)) & HFA384x_INTEN_WTERR))
#define		HFA384x_INTEN_WTERR_SET(value)		((uint16_t)(((uint16_t)(value)) << 14))
#define		HFA384x_INTEN_ISINFDROP(value)		((uint16_t)(((uint16_t)(value)) & HFA384x_INTEN_INFDROP))
#define		HFA384x_INTEN_INFDROP_SET(value)	((uint16_t)(((uint16_t)(value)) << 13))
#define		HFA384x_INTEN_ISINFO(value)		((uint16_t)(((uint16_t)(value)) & HFA384x_INTEN_INFO))
#define		HFA384x_INTEN_INFO_SET(value)		((uint16_t)(((uint16_t)(value)) << 7))
#define		HFA384x_INTEN_ISDTIM(value)		((uint16_t)(((uint16_t)(value)) & HFA384x_INTEN_DTIM))
#define		HFA384x_INTEN_DTIM_SET(value)		((uint16_t)(((uint16_t)(value)) << 5))
#define		HFA384x_INTEN_ISCMD(value)		((uint16_t)(((uint16_t)(value)) & HFA384x_INTEN_CMD))
#define		HFA384x_INTEN_CMD_SET(value)		((uint16_t)(((uint16_t)(value)) << 4))
#define		HFA384x_INTEN_ISALLOC(value)		((uint16_t)(((uint16_t)(value)) & HFA384x_INTEN_ALLOC))
#define		HFA384x_INTEN_ALLOC_SET(value)		((uint16_t)(((uint16_t)(value)) << 3))
#define		HFA384x_INTEN_ISTXEXC(value)		((uint16_t)(((uint16_t)(value)) & HFA384x_INTEN_TXEXC))
#define		HFA384x_INTEN_TXEXC_SET(value)		((uint16_t)(((uint16_t)(value)) << 2))
#define		HFA384x_INTEN_ISTX(value)		((uint16_t)(((uint16_t)(value)) & HFA384x_INTEN_TX))
#define		HFA384x_INTEN_TX_SET(value)		((uint16_t)(((uint16_t)(value)) << 1))
#define		HFA384x_INTEN_ISRX(value)		((uint16_t)(((uint16_t)(value)) & HFA384x_INTEN_RX))
#define		HFA384x_INTEN_RX_SET(value)		((uint16_t)(((uint16_t)(value)) << 0))

#define		HFA384x_EVACK_ISTICK(value)		((uint16_t)(((uint16_t)(value)) & HFA384x_EVACK_TICK))
#define		HFA384x_EVACK_TICK_SET(value)		((uint16_t)(((uint16_t)(value)) << 15))
#define		HFA384x_EVACK_ISWTERR(value)		((uint16_t)(((uint16_t)(value)) & HFA384x_EVACK_WTERR))
#define		HFA384x_EVACK_WTERR_SET(value)		((uint16_t)(((uint16_t)(value)) << 14))
#define		HFA384x_EVACK_ISINFDROP(value)		((uint16_t)(((uint16_t)(value)) & HFA384x_EVACK_INFDROP))
#define		HFA384x_EVACK_INFDROP_SET(value)	((uint16_t)(((uint16_t)(value)) << 13))
#define		HFA384x_EVACK_ISINFO(value)		((uint16_t)(((uint16_t)(value)) & HFA384x_EVACK_INFO))
#define		HFA384x_EVACK_INFO_SET(value)		((uint16_t)(((uint16_t)(value)) << 7))
#define		HFA384x_EVACK_ISDTIM(value)		((uint16_t)(((uint16_t)(value)) & HFA384x_EVACK_DTIM))
#define		HFA384x_EVACK_DTIM_SET(value)		((uint16_t)(((uint16_t)(value)) << 5))
#define		HFA384x_EVACK_ISCMD(value)		((uint16_t)(((uint16_t)(value)) & HFA384x_EVACK_CMD))
#define		HFA384x_EVACK_CMD_SET(value)		((uint16_t)(((uint16_t)(value)) << 4))
#define		HFA384x_EVACK_ISALLOC(value)		((uint16_t)(((uint16_t)(value)) & HFA384x_EVACK_ALLOC))
#define		HFA384x_EVACK_ALLOC_SET(value)		((uint16_t)(((uint16_t)(value)) << 3))
#define		HFA384x_EVACK_ISTXEXC(value)		((uint16_t)(((uint16_t)(value)) & HFA384x_EVACK_TXEXC))
#define		HFA384x_EVACK_TXEXC_SET(value)		((uint16_t)(((uint16_t)(value)) << 2))
#define		HFA384x_EVACK_ISTX(value)		((uint16_t)(((uint16_t)(value)) & HFA384x_EVACK_TX))
#define		HFA384x_EVACK_TX_SET(value)		((uint16_t)(((uint16_t)(value)) << 1))
#define		HFA384x_EVACK_ISRX(value)		((uint16_t)(((uint16_t)(value)) & HFA384x_EVACK_RX))
#define		HFA384x_EVACK_RX_SET(value)		((uint16_t)(((uint16_t)(value)) << 0))

#define		HFA384x_CONTROL_AUXEN_SET(value)	((uint16_t)(((uint16_t)(value)) << 14))
#define		HFA384x_CONTROL_AUXEN_GET(value)	((uint16_t)(((uint16_t)(value)) >> 14))

/* Byte Order */
#ifdef __KERNEL__
#define hfa384x2host_16(n)	(__le16_to_cpu((uint16_t)(n)))
#define hfa384x2host_32(n)	(__le32_to_cpu((uint32_t)(n)))
#define host2hfa384x_16(n)	(__cpu_to_le16((uint16_t)(n)))
#define host2hfa384x_32(n)	(__cpu_to_le32((uint32_t)(n)))
#endif

/* Host Maintained State Info */
#define HFA384x_STATE_PREINIT	0
#define HFA384x_STATE_INIT	1
#define HFA384x_STATE_RUNNING	2

/*=============================================================*/
/*------ Types and their related constants --------------------*/

#define HFA384x_HOSTAUTHASSOC_HOSTAUTH   BIT0
#define HFA384x_HOSTAUTHASSOC_HOSTASSOC  BIT1

#define HFA384x_WHAHANDLING_DISABLED     0
#define HFA384x_WHAHANDLING_PASSTHROUGH  BIT1

/*-------------------------------------------------------------*/
/* Commonly used basic types */
typedef struct hfa384x_bytestr
{
	uint16_t	len;
	uint8_t	data[0];
} __WLAN_ATTRIB_PACK__ hfa384x_bytestr_t;

typedef struct hfa384x_bytestr32
{
	uint16_t	len;
	uint8_t	data[32];
} __WLAN_ATTRIB_PACK__ hfa384x_bytestr32_t;

/*--------------------------------------------------------------------
Configuration Record Structures:
	Network Parameters, Static Configuration Entities
--------------------------------------------------------------------*/
/* Prototype structure: all configuration record structures start with
these members */

typedef struct hfa384x_record
{
	uint16_t	reclen;
	uint16_t	rid;
} __WLAN_ATTRIB_PACK__ hfa384x_rec_t;

typedef struct hfa384x_record16
{
	uint16_t	reclen;
	uint16_t	rid;
	uint16_t	val;
} __WLAN_ATTRIB_PACK__ hfa384x_rec16_t;

typedef struct hfa384x_record32
{
	uint16_t	reclen;
	uint16_t	rid;
	uint32_t	val;
} __WLAN_ATTRIB_PACK__ hfa384x_rec32;

/*-- Hardware/Firmware Component Information ----------*/
typedef struct hfa384x_compident
{
	uint16_t	id;
	uint16_t	variant;
	uint16_t	major;
	uint16_t	minor;
} __WLAN_ATTRIB_PACK__ hfa384x_compident_t;

typedef struct hfa384x_caplevel
{
	uint16_t	role;
	uint16_t	id;
	uint16_t	variant;
	uint16_t	bottom;
	uint16_t	top;
} __WLAN_ATTRIB_PACK__ hfa384x_caplevel_t;

/*-- Configuration Record: cnfPortType --*/
typedef struct hfa384x_cnfPortType
{
	uint16_t	cnfPortType;
} __WLAN_ATTRIB_PACK__ hfa384x_cnfPortType_t;

/*-- Configuration Record: cnfOwnMACAddress --*/
typedef struct hfa384x_cnfOwnMACAddress
{
	uint8_t	cnfOwnMACAddress[6];
} __WLAN_ATTRIB_PACK__ hfa384x_cnfOwnMACAddress_t;

/*-- Configuration Record: cnfDesiredSSID --*/
typedef struct hfa384x_cnfDesiredSSID
{
	uint8_t	cnfDesiredSSID[34];
} __WLAN_ATTRIB_PACK__ hfa384x_cnfDesiredSSID_t;

/*-- Configuration Record: cnfOwnChannel --*/
typedef struct hfa384x_cnfOwnChannel
{
	uint16_t	cnfOwnChannel;
} __WLAN_ATTRIB_PACK__ hfa384x_cnfOwnChannel_t;

/*-- Configuration Record: cnfOwnSSID --*/
typedef struct hfa384x_cnfOwnSSID
{
	uint8_t	cnfOwnSSID[34];
} __WLAN_ATTRIB_PACK__ hfa384x_cnfOwnSSID_t;

/*-- Configuration Record: cnfOwnATIMWindow --*/
typedef struct hfa384x_cnfOwnATIMWindow
{
	uint16_t	cnfOwnATIMWindow;
} __WLAN_ATTRIB_PACK__ hfa384x_cnfOwnATIMWindow_t;

/*-- Configuration Record: cnfSystemScale --*/
typedef struct hfa384x_cnfSystemScale
{
	uint16_t	cnfSystemScale;
} __WLAN_ATTRIB_PACK__ hfa384x_cnfSystemScale_t;

/*-- Configuration Record: cnfMaxDataLength --*/
typedef struct hfa384x_cnfMaxDataLength
{
	uint16_t	cnfMaxDataLength;
} __WLAN_ATTRIB_PACK__ hfa384x_cnfMaxDataLength_t;

/*-- Configuration Record: cnfWDSAddress --*/
typedef struct hfa384x_cnfWDSAddress
{
	uint8_t	cnfWDSAddress[6];
} __WLAN_ATTRIB_PACK__ hfa384x_cnfWDSAddress_t;

/*-- Configuration Record: cnfPMEnabled --*/
typedef struct hfa384x_cnfPMEnabled
{
	uint16_t	cnfPMEnabled;
} __WLAN_ATTRIB_PACK__ hfa384x_cnfPMEnabled_t;

/*-- Configuration Record: cnfPMEPS --*/
typedef struct hfa384x_cnfPMEPS
{
	uint16_t	cnfPMEPS;
} __WLAN_ATTRIB_PACK__ hfa384x_cnfPMEPS_t;

/*-- Configuration Record: cnfMulticastReceive --*/
typedef struct hfa384x_cnfMulticastReceive
{
	uint16_t	cnfMulticastReceive;
} __WLAN_ATTRIB_PACK__ hfa384x_cnfMulticastReceive_t;

/*-- Configuration Record: cnfAuthentication --*/
#define HFA384x_CNFAUTHENTICATION_OPENSYSTEM	0x0001
#define HFA384x_CNFAUTHENTICATION_SHAREDKEY	0x0002
#define HFA384x_CNFAUTHENTICATION_LEAP     	0x0004

/*-- Configuration Record: cnfMaxSleepDuration --*/
typedef struct hfa384x_cnfMaxSleepDuration
{
	uint16_t	cnfMaxSleepDuration;
} __WLAN_ATTRIB_PACK__ hfa384x_cnfMaxSleepDuration_t;

/*-- Configuration Record: cnfPMHoldoverDuration --*/
typedef struct hfa384x_cnfPMHoldoverDuration
{
	uint16_t	cnfPMHoldoverDuration;
} __WLAN_ATTRIB_PACK__ hfa384x_cnfPMHoldoverDuration_t;

/*-- Configuration Record: cnfOwnName --*/
typedef struct hfa384x_cnfOwnName
{
	uint8_t	cnfOwnName[34];
} __WLAN_ATTRIB_PACK__ hfa384x_cnfOwnName_t;

/*-- Configuration Record: cnfOwnDTIMPeriod --*/
typedef struct hfa384x_cnfOwnDTIMPeriod
{
	uint16_t	cnfOwnDTIMPeriod;
} __WLAN_ATTRIB_PACK__ hfa384x_cnfOwnDTIMPeriod_t;

/*-- Configuration Record: cnfWDSAddress --*/
typedef struct hfa384x_cnfWDSAddressN
{
	uint8_t	cnfWDSAddress[6];
} __WLAN_ATTRIB_PACK__ hfa384x_cnfWDSAddressN_t;

/*-- Configuration Record: cnfMulticastPMBuffering --*/
typedef struct hfa384x_cnfMulticastPMBuffering
{
	uint16_t	cnfMulticastPMBuffering;
} __WLAN_ATTRIB_PACK__ hfa384x_cnfMulticastPMBuffering_t;

/*--------------------------------------------------------------------
Configuration Record Structures:
	Network Parameters, Dynamic Configuration Entities
--------------------------------------------------------------------*/

/*-- Configuration Record: GroupAddresses --*/
typedef struct hfa384x_GroupAddresses
{
	uint8_t	MACAddress[16][6];
} __WLAN_ATTRIB_PACK__ hfa384x_GroupAddresses_t;

/*-- Configuration Record: CreateIBSS --*/
typedef struct hfa384x_CreateIBSS
{
	uint16_t	CreateIBSS;
} __WLAN_ATTRIB_PACK__ hfa384x_CreateIBSS_t;

#define HFA384x_CREATEIBSS_JOINCREATEIBSS          0
#define HFA384x_CREATEIBSS_JOINESS_JOINCREATEIBSS  1
#define HFA384x_CREATEIBSS_JOINIBSS                2
#define HFA384x_CREATEIBSS_JOINESS_JOINIBSS        3

/*-- Configuration Record: FragmentationThreshold --*/
typedef struct hfa384x_FragmentationThreshold
{
	uint16_t	FragmentationThreshold;
} __WLAN_ATTRIB_PACK__ hfa384x_FragmentationThreshold_t;

/*-- Configuration Record: RTSThreshold --*/
typedef struct hfa384x_RTSThreshold
{
	uint16_t	RTSThreshold;
} __WLAN_ATTRIB_PACK__ hfa384x_RTSThreshold_t;

/*-- Configuration Record: TxRateControl --*/
typedef struct hfa384x_TxRateControl
{
	uint16_t	TxRateControl;
} __WLAN_ATTRIB_PACK__ hfa384x_TxRateControl_t;

/*-- Configuration Record: PromiscuousMode --*/
typedef struct hfa384x_PromiscuousMode
{
	uint16_t	PromiscuousMode;
} __WLAN_ATTRIB_PACK__ hfa384x_PromiscuousMode_t;

/*-- Configuration Record: ScanRequest (data portion only) --*/
typedef struct hfa384x_ScanRequest_data
{
	uint16_t	channelList;
	uint16_t	txRate;
} __WLAN_ATTRIB_PACK__ hfa384x_ScanRequest_data_t;

/*-- Configuration Record: HostScanRequest (data portion only) --*/
typedef struct hfa384x_HostScanRequest_data
{
	uint16_t	channelList;
	uint16_t	txRate;
	hfa384x_bytestr32_t ssid;
} __WLAN_ATTRIB_PACK__ hfa384x_HostScanRequest_data_t;

/*-- Configuration Record: JoinRequest (data portion only) --*/
typedef struct hfa384x_JoinRequest_data
{
	uint8_t	bssid[WLAN_BSSID_LEN];
	uint16_t	channel;
} __WLAN_ATTRIB_PACK__ hfa384x_JoinRequest_data_t;

/*-- Configuration Record: authenticateStation (data portion only) --*/
typedef struct hfa384x_authenticateStation_data
{
	uint8_t	address[WLAN_ADDR_LEN];
	uint16_t	status;
	uint16_t	algorithm;
} __WLAN_ATTRIB_PACK__ hfa384x_authenticateStation_data_t;

/*-- Configuration Record: associateStation (data portion only) --*/
typedef struct hfa384x_associateStation_data
{
	uint8_t	address[WLAN_ADDR_LEN];
	uint16_t	status;
	uint16_t	type;
} __WLAN_ATTRIB_PACK__ hfa384x_associateStation_data_t;

/*-- Configuration Record: ChannelInfoRequest (data portion only) --*/
typedef struct hfa384x_ChannelInfoRequest_data
{
	uint16_t	channelList;
	uint16_t	channelDwellTime;
} __WLAN_ATTRIB_PACK__ hfa384x_ChannelInfoRequest_data_t;

/*-- Configuration Record: WEPKeyMapping (data portion only) --*/
typedef struct hfa384x_WEPKeyMapping
{
	uint8_t	address[WLAN_ADDR_LEN];
	uint16_t	key_index;
	uint8_t 	key[16];
	uint8_t 	mic_transmit_key[4];
	uint8_t 	mic_receive_key[4];
} __WLAN_ATTRIB_PACK__ hfa384x_WEPKeyMapping_t;

/*-- Configuration Record: WPAData       (data portion only) --*/
typedef struct hfa384x_WPAData
{
	uint16_t	datalen;
        uint8_t 	data[0]; // max 80
} __WLAN_ATTRIB_PACK__ hfa384x_WPAData_t;

/*--------------------------------------------------------------------
Configuration Record Structures: Behavior Parameters
--------------------------------------------------------------------*/

/*-- Configuration Record: TickTime --*/
typedef struct hfa384x_TickTime
{
	uint16_t	TickTime;
} __WLAN_ATTRIB_PACK__ hfa384x_TickTime_t;

/*--------------------------------------------------------------------
Information Record Structures: NIC Information
--------------------------------------------------------------------*/

/*-- Information Record: MaxLoadTime --*/
typedef struct hfa384x_MaxLoadTime
{
	uint16_t	MaxLoadTime;
} __WLAN_ATTRIB_PACK__ hfa384x_MaxLoadTime_t;

/*-- Information Record: DownLoadBuffer --*/
/* NOTE: The page and offset are in AUX format */
typedef struct hfa384x_downloadbuffer
{
	uint16_t	page;
	uint16_t	offset;
	uint16_t	len;
} __WLAN_ATTRIB_PACK__ hfa384x_downloadbuffer_t;

/*-- Information Record: PRIIdentity --*/
typedef struct hfa384x_PRIIdentity
{
	uint16_t	PRICompID;
	uint16_t	PRIVariant;
	uint16_t	PRIMajorVersion;
	uint16_t	PRIMinorVersion;
} __WLAN_ATTRIB_PACK__ hfa384x_PRIIdentity_t;

/*-- Information Record: PRISupRange --*/
typedef struct hfa384x_PRISupRange
{
	uint16_t	PRIRole;
	uint16_t	PRIID;
	uint16_t	PRIVariant;
	uint16_t	PRIBottom;
	uint16_t	PRITop;
} __WLAN_ATTRIB_PACK__ hfa384x_PRISupRange_t;

/*-- Information Record: CFIActRanges --*/
typedef struct hfa384x_CFIActRanges
{
	uint16_t	CFIRole;
	uint16_t	CFIID;
	uint16_t	CFIVariant;
	uint16_t	CFIBottom;
	uint16_t	CFITop;
} __WLAN_ATTRIB_PACK__ hfa384x_CFIActRanges_t;

/*-- Information Record: NICSerialNumber --*/
typedef struct hfa384x_NICSerialNumber
{
	uint8_t	NICSerialNumber[12];
} __WLAN_ATTRIB_PACK__ hfa384x_NICSerialNumber_t;

/*-- Information Record: NICIdentity --*/
typedef struct hfa384x_NICIdentity
{
	uint16_t	NICCompID;
	uint16_t	NICVariant;
	uint16_t	NICMajorVersion;
	uint16_t	NICMinorVersion;
} __WLAN_ATTRIB_PACK__ hfa384x_NICIdentity_t;

/*-- Information Record: MFISupRange --*/
typedef struct hfa384x_MFISupRange
{
	uint16_t	MFIRole;
	uint16_t	MFIID;
	uint16_t	MFIVariant;
	uint16_t	MFIBottom;
	uint16_t	MFITop;
} __WLAN_ATTRIB_PACK__ hfa384x_MFISupRange_t;

/*-- Information Record: CFISupRange --*/
typedef struct hfa384x_CFISupRange
{
	uint16_t	CFIRole;
	uint16_t	CFIID;
	uint16_t	CFIVariant;
	uint16_t	CFIBottom;
	uint16_t	CFITop;
} __WLAN_ATTRIB_PACK__ hfa384x_CFISupRange_t;

/*-- Information Record: BUILDSEQ:BuildSeq --*/
typedef struct hfa384x_BuildSeq {
	uint16_t	primary;
	uint16_t	secondary;
} __WLAN_ATTRIB_PACK__ hfa384x_BuildSeq_t;

/*-- Information Record: FWID --*/
#define HFA384x_FWID_LEN	14
typedef struct hfa384x_FWID {
	uint8_t	primary[HFA384x_FWID_LEN];
	uint8_t	secondary[HFA384x_FWID_LEN];
} __WLAN_ATTRIB_PACK__ hfa384x_FWID_t;

/*-- Information Record: ChannelList --*/
typedef struct hfa384x_ChannelList
{
	uint16_t	ChannelList;
} __WLAN_ATTRIB_PACK__ hfa384x_ChannelList_t;

/*-- Information Record: RegulatoryDomains --*/
typedef struct hfa384x_RegulatoryDomains
{
	uint8_t	RegulatoryDomains[12];
} __WLAN_ATTRIB_PACK__ hfa384x_RegulatoryDomains_t;

/*-- Information Record: TempType --*/
typedef struct hfa384x_TempType
{
	uint16_t	TempType;
} __WLAN_ATTRIB_PACK__ hfa384x_TempType_t;

/*-- Information Record: CIS --*/
typedef struct hfa384x_CIS
{
	uint8_t	CIS[480];
} __WLAN_ATTRIB_PACK__ hfa384x_CIS_t;

/*-- Information Record: STAIdentity --*/
typedef struct hfa384x_STAIdentity
{
	uint16_t	STACompID;
	uint16_t	STAVariant;
	uint16_t	STAMajorVersion;
	uint16_t	STAMinorVersion;
} __WLAN_ATTRIB_PACK__ hfa384x_STAIdentity_t;

/*-- Information Record: STASupRange --*/
typedef struct hfa384x_STASupRange
{
	uint16_t	STARole;
	uint16_t	STAID;
	uint16_t	STAVariant;
	uint16_t	STABottom;
	uint16_t	STATop;
} __WLAN_ATTRIB_PACK__ hfa384x_STASupRange_t;

/*-- Information Record: MFIActRanges --*/
typedef struct hfa384x_MFIActRanges
{
	uint16_t	MFIRole;
	uint16_t	MFIID;
	uint16_t	MFIVariant;
	uint16_t	MFIBottom;
	uint16_t	MFITop;
} __WLAN_ATTRIB_PACK__ hfa384x_MFIActRanges_t;

/*--------------------------------------------------------------------
Information Record Structures: NIC Information
--------------------------------------------------------------------*/

/*-- Information Record: PortStatus --*/
typedef struct hfa384x_PortStatus
{
	uint16_t	PortStatus;
} __WLAN_ATTRIB_PACK__ hfa384x_PortStatus_t;

#define HFA384x_PSTATUS_DISABLED	((uint16_t)1)
#define HFA384x_PSTATUS_SEARCHING	((uint16_t)2)
#define HFA384x_PSTATUS_CONN_IBSS	((uint16_t)3)
#define HFA384x_PSTATUS_CONN_ESS	((uint16_t)4)
#define HFA384x_PSTATUS_OUTOFRANGE	((uint16_t)5)
#define HFA384x_PSTATUS_CONN_WDS	((uint16_t)6)

/*-- Information Record: CurrentSSID --*/
typedef struct hfa384x_CurrentSSID
{
	uint8_t	CurrentSSID[34];
} __WLAN_ATTRIB_PACK__ hfa384x_CurrentSSID_t;

/*-- Information Record: CurrentBSSID --*/
typedef struct hfa384x_CurrentBSSID
{
	uint8_t	CurrentBSSID[6];
} __WLAN_ATTRIB_PACK__ hfa384x_CurrentBSSID_t;

/*-- Information Record: commsquality --*/
typedef struct hfa384x_commsquality
{
	uint16_t	CQ_currBSS;
	uint16_t	ASL_currBSS;
	uint16_t	ANL_currFC;
} __WLAN_ATTRIB_PACK__ hfa384x_commsquality_t;

/*-- Information Record: dmbcommsquality --*/
typedef struct hfa384x_dbmcommsquality
{
	uint16_t	CQdbm_currBSS;
	uint16_t	ASLdbm_currBSS;
	uint16_t	ANLdbm_currFC;
} __WLAN_ATTRIB_PACK__ hfa384x_dbmcommsquality_t;

/*-- Information Record: CurrentTxRate --*/
typedef struct hfa384x_CurrentTxRate
{
	uint16_t	CurrentTxRate;
} __WLAN_ATTRIB_PACK__ hfa384x_CurrentTxRate_t;

/*-- Information Record: CurrentBeaconInterval --*/
typedef struct hfa384x_CurrentBeaconInterval
{
	uint16_t	CurrentBeaconInterval;
} __WLAN_ATTRIB_PACK__ hfa384x_CurrentBeaconInterval_t;

/*-- Information Record: CurrentScaleThresholds --*/
typedef struct hfa384x_CurrentScaleThresholds
{
	uint16_t	EnergyDetectThreshold;
	uint16_t	CarrierDetectThreshold;
	uint16_t	DeferDetectThreshold;
	uint16_t	CellSearchThreshold; /* Stations only */
	uint16_t	DeadSpotThreshold; /* Stations only */
} __WLAN_ATTRIB_PACK__ hfa384x_CurrentScaleThresholds_t;

/*-- Information Record: ProtocolRspTime --*/
typedef struct hfa384x_ProtocolRspTime
{
	uint16_t	ProtocolRspTime;
} __WLAN_ATTRIB_PACK__ hfa384x_ProtocolRspTime_t;

/*-- Information Record: ShortRetryLimit --*/
typedef struct hfa384x_ShortRetryLimit
{
	uint16_t	ShortRetryLimit;
} __WLAN_ATTRIB_PACK__ hfa384x_ShortRetryLimit_t;

/*-- Information Record: LongRetryLimit --*/
typedef struct hfa384x_LongRetryLimit
{
	uint16_t	LongRetryLimit;
} __WLAN_ATTRIB_PACK__ hfa384x_LongRetryLimit_t;

/*-- Information Record: MaxTransmitLifetime --*/
typedef struct hfa384x_MaxTransmitLifetime
{
	uint16_t	MaxTransmitLifetime;
} __WLAN_ATTRIB_PACK__ hfa384x_MaxTransmitLifetime_t;

/*-- Information Record: MaxReceiveLifetime --*/
typedef struct hfa384x_MaxReceiveLifetime
{
	uint16_t	MaxReceiveLifetime;
} __WLAN_ATTRIB_PACK__ hfa384x_MaxReceiveLifetime_t;

/*-- Information Record: CFPollable --*/
typedef struct hfa384x_CFPollable
{
	uint16_t	CFPollable;
} __WLAN_ATTRIB_PACK__ hfa384x_CFPollable_t;

/*-- Information Record: AuthenticationAlgorithms --*/
typedef struct hfa384x_AuthenticationAlgorithms
{
	uint16_t	AuthenticationType;
	uint16_t	TypeEnabled;
} __WLAN_ATTRIB_PACK__ hfa384x_AuthenticationAlgorithms_t;

/*-- Information Record: AuthenticationAlgorithms
(data only --*/
typedef struct hfa384x_AuthenticationAlgorithms_data
{
	uint16_t	AuthenticationType;
	uint16_t	TypeEnabled;
} __WLAN_ATTRIB_PACK__ hfa384x_AuthenticationAlgorithms_data_t;

/*-- Information Record: PrivacyOptionImplemented --*/
typedef struct hfa384x_PrivacyOptionImplemented
{
	uint16_t	PrivacyOptionImplemented;
} __WLAN_ATTRIB_PACK__ hfa384x_PrivacyOptionImplemented_t;

/*-- Information Record: OwnMACAddress --*/
typedef struct hfa384x_OwnMACAddress
{
	uint8_t	OwnMACAddress[6];
} __WLAN_ATTRIB_PACK__ hfa384x_OwnMACAddress_t;

/*-- Information Record: PCFInfo --*/
typedef struct hfa384x_PCFInfo
{
	uint16_t	MediumOccupancyLimit;
	uint16_t	CFPPeriod;
	uint16_t	CFPMaxDuration;
	uint16_t	CFPFlags;
} __WLAN_ATTRIB_PACK__ hfa384x_PCFInfo_t;

/*-- Information Record: PCFInfo (data portion only) --*/
typedef struct hfa384x_PCFInfo_data
{
	uint16_t	MediumOccupancyLimit;
	uint16_t	CFPPeriod;
	uint16_t	CFPMaxDuration;
	uint16_t	CFPFlags;
} __WLAN_ATTRIB_PACK__ hfa384x_PCFInfo_data_t;

/*--------------------------------------------------------------------
Information Record Structures: Modem Information Records
--------------------------------------------------------------------*/

/*-- Information Record: PHYType --*/
typedef struct hfa384x_PHYType
{
	uint16_t	PHYType;
} __WLAN_ATTRIB_PACK__ hfa384x_PHYType_t;

/*-- Information Record: CurrentChannel --*/
typedef struct hfa384x_CurrentChannel
{
	uint16_t	CurrentChannel;
} __WLAN_ATTRIB_PACK__ hfa384x_CurrentChannel_t;

/*-- Information Record: CurrentPowerState --*/
typedef struct hfa384x_CurrentPowerState
{
	uint16_t	CurrentPowerState;
} __WLAN_ATTRIB_PACK__ hfa384x_CurrentPowerState_t;

/*-- Information Record: CCAMode --*/
typedef struct hfa384x_CCAMode
{
	uint16_t	CCAMode;
} __WLAN_ATTRIB_PACK__ hfa384x_CCAMode_t;

/*-- Information Record: SupportedDataRates --*/
typedef struct hfa384x_SupportedDataRates
{
	uint8_t	SupportedDataRates[10];
} __WLAN_ATTRIB_PACK__ hfa384x_SupportedDataRates_t;

/*-- Information Record: LFOStatus --*/
typedef struct hfa384x_LFOStatus
{
	uint16_t  TestResults;
	uint16_t  LFOResult;
	uint16_t  VRHFOResult;
} __WLAN_ATTRIB_PACK__ hfa384x_LFOStatus_t;

#define HFA384x_TESTRESULT_ALLPASSED    BIT0
#define HFA384x_TESTRESULT_LFO_FAIL     BIT1
#define HFA384x_TESTRESULT_VR_HF0_FAIL  BIT2
#define HFA384x_HOST_FIRM_COORDINATE    BIT7
#define HFA384x_TESTRESULT_COORDINATE   BIT15

/*-- Information Record: LEDControl --*/
typedef struct hfa384x_LEDControl
{
	uint16_t  searching_on;
	uint16_t  searching_off;
	uint16_t  assoc_on;
	uint16_t  assoc_off;
	uint16_t  activity;
} __WLAN_ATTRIB_PACK__ hfa384x_LEDControl_t;

/*--------------------------------------------------------------------
                 FRAME DESCRIPTORS AND FRAME STRUCTURES

FRAME DESCRIPTORS: Offsets

----------------------------------------------------------------------
Control Info (offset 44-51)
--------------------------------------------------------------------*/
#define		HFA384x_FD_STATUS_OFF			((uint16_t)0x44)
#define		HFA384x_FD_TIME_OFF			((uint16_t)0x46)
#define		HFA384x_FD_SWSUPPORT_OFF		((uint16_t)0x4A)
#define		HFA384x_FD_SILENCE_OFF			((uint16_t)0x4A)
#define		HFA384x_FD_SIGNAL_OFF			((uint16_t)0x4B)
#define		HFA384x_FD_RATE_OFF			((uint16_t)0x4C)
#define		HFA384x_FD_RXFLOW_OFF			((uint16_t)0x4D)
#define		HFA384x_FD_RESERVED_OFF			((uint16_t)0x4E)
#define		HFA384x_FD_TXCONTROL_OFF		((uint16_t)0x50)
/*--------------------------------------------------------------------
802.11 Header (offset 52-6B)
--------------------------------------------------------------------*/
#define		HFA384x_FD_FRAMECONTROL_OFF		((uint16_t)0x52)
#define		HFA384x_FD_DURATIONID_OFF		((uint16_t)0x54)
#define		HFA384x_FD_ADDRESS1_OFF			((uint16_t)0x56)
#define		HFA384x_FD_ADDRESS2_OFF			((uint16_t)0x5C)
#define		HFA384x_FD_ADDRESS3_OFF			((uint16_t)0x62)
#define		HFA384x_FD_SEQCONTROL_OFF		((uint16_t)0x68)
#define		HFA384x_FD_ADDRESS4_OFF			((uint16_t)0x6A)
#define		HFA384x_FD_DATALEN_OFF			((uint16_t)0x70)
/*--------------------------------------------------------------------
802.3 Header (offset 72-7F)
--------------------------------------------------------------------*/
#define		HFA384x_FD_DESTADDRESS_OFF		((uint16_t)0x72)
#define		HFA384x_FD_SRCADDRESS_OFF		((uint16_t)0x78)
#define		HFA384x_FD_DATALENGTH_OFF		((uint16_t)0x7E)

/*--------------------------------------------------------------------
FRAME STRUCTURES: Communication Frames
----------------------------------------------------------------------
Communication Frames: Transmit Frames
--------------------------------------------------------------------*/
/*-- Communication Frame: Transmit Frame Structure --*/
typedef struct hfa384x_tx_frame
{
	uint16_t	status;
	uint16_t	reserved1;
	uint16_t	reserved2;
	uint32_t	sw_support;
	uint8_t	tx_retrycount;
	uint8_t   tx_rate;
	uint16_t	tx_control;

	/*-- 802.11 Header Information --*/

	uint16_t	frame_control;
	uint16_t	duration_id;
	uint8_t	address1[6];
	uint8_t	address2[6];
	uint8_t	address3[6];
	uint16_t	sequence_control;
	uint8_t	address4[6];
	uint16_t	data_len; /* little endian format */

	/*-- 802.3 Header Information --*/

	uint8_t	dest_addr[6];
	uint8_t	src_addr[6];
	uint16_t	data_length; /* big endian format */
} __WLAN_ATTRIB_PACK__ hfa384x_tx_frame_t;
/*--------------------------------------------------------------------
Communication Frames: Field Masks for Transmit Frames
--------------------------------------------------------------------*/
/*-- Status Field --*/
#define		HFA384x_TXSTATUS_ACKERR			((uint16_t)BIT5)
#define		HFA384x_TXSTATUS_FORMERR		((uint16_t)BIT3)
#define		HFA384x_TXSTATUS_DISCON			((uint16_t)BIT2)
#define		HFA384x_TXSTATUS_AGEDERR		((uint16_t)BIT1)
#define		HFA384x_TXSTATUS_RETRYERR		((uint16_t)BIT0)
/*-- Transmit Control Field --*/
#define		HFA384x_TX_CFPOLL			((uint16_t)BIT12)
#define		HFA384x_TX_PRST				((uint16_t)BIT11)
#define		HFA384x_TX_MACPORT			((uint16_t)(BIT10 | BIT9 | BIT8))
#define		HFA384x_TX_NOENCRYPT			((uint16_t)BIT7)
#define		HFA384x_TX_RETRYSTRAT			((uint16_t)(BIT6 | BIT5))
#define		HFA384x_TX_STRUCTYPE			((uint16_t)(BIT4 | BIT3))
#define		HFA384x_TX_TXEX				((uint16_t)BIT2)
#define		HFA384x_TX_TXOK				((uint16_t)BIT1)
/*--------------------------------------------------------------------
Communication Frames: Test/Get/Set Field Values for Transmit Frames
--------------------------------------------------------------------*/
/*-- Status Field --*/
#define HFA384x_TXSTATUS_ISERROR(v)	\
	(((uint16_t)(v))&\
	(HFA384x_TXSTATUS_ACKERR|HFA384x_TXSTATUS_FORMERR|\
	HFA384x_TXSTATUS_DISCON|HFA384x_TXSTATUS_AGEDERR|\
	HFA384x_TXSTATUS_RETRYERR))

#define	HFA384x_TXSTATUS_ISACKERR(v)	((uint16_t)(((uint16_t)(v)) & HFA384x_TXSTATUS_ACKERR))
#define	HFA384x_TXSTATUS_ISFORMERR(v)	((uint16_t)(((uint16_t)(v)) & HFA384x_TXSTATUS_FORMERR))
#define	HFA384x_TXSTATUS_ISDISCON(v)	((uint16_t)(((uint16_t)(v)) & HFA384x_TXSTATUS_DISCON))
#define	HFA384x_TXSTATUS_ISAGEDERR(v)	((uint16_t)(((uint16_t)(v)) & HFA384x_TXSTATUS_AGEDERR))
#define	HFA384x_TXSTATUS_ISRETRYERR(v)	((uint16_t)(((uint16_t)(v)) & HFA384x_TXSTATUS_RETRYERR))

#define	HFA384x_TX_GET(v,m,s)		((((uint16_t)(v))&((uint16_t)(m)))>>((uint16_t)(s)))
#define	HFA384x_TX_SET(v,m,s)		((((uint16_t)(v))<<((uint16_t)(s)))&((uint16_t)(m)))

#define	HFA384x_TX_CFPOLL_GET(v)	HFA384x_TX_GET(v, HFA384x_TX_CFPOLL,12)
#define	HFA384x_TX_CFPOLL_SET(v)	HFA384x_TX_SET(v, HFA384x_TX_CFPOLL,12)
#define	HFA384x_TX_PRST_GET(v)		HFA384x_TX_GET(v, HFA384x_TX_PRST,11)
#define	HFA384x_TX_PRST_SET(v)		HFA384x_TX_SET(v, HFA384x_TX_PRST,11)
#define	HFA384x_TX_MACPORT_GET(v)	HFA384x_TX_GET(v, HFA384x_TX_MACPORT, 8)
#define	HFA384x_TX_MACPORT_SET(v)	HFA384x_TX_SET(v, HFA384x_TX_MACPORT, 8)
#define	HFA384x_TX_NOENCRYPT_GET(v)	HFA384x_TX_GET(v, HFA384x_TX_NOENCRYPT, 7)
#define	HFA384x_TX_NOENCRYPT_SET(v)	HFA384x_TX_SET(v, HFA384x_TX_NOENCRYPT, 7)
#define	HFA384x_TX_RETRYSTRAT_GET(v)	HFA384x_TX_GET(v, HFA384x_TX_RETRYSTRAT, 5)
#define	HFA384x_TX_RETRYSTRAT_SET(v)	HFA384x_TX_SET(v, HFA384x_TX_RETRYSTRAT, 5)
#define	HFA384x_TX_STRUCTYPE_GET(v)	HFA384x_TX_GET(v, HFA384x_TX_STRUCTYPE, 3)
#define	HFA384x_TX_STRUCTYPE_SET(v)	HFA384x_TX_SET(v, HFA384x_TX_STRUCTYPE, 3)
#define	HFA384x_TX_TXEX_GET(v)		HFA384x_TX_GET(v, HFA384x_TX_TXEX, 2)
#define	HFA384x_TX_TXEX_SET(v)		HFA384x_TX_SET(v, HFA384x_TX_TXEX, 2)
#define	HFA384x_TX_TXOK_GET(v)		HFA384x_TX_GET(v, HFA384x_TX_TXOK, 1)
#define	HFA384x_TX_TXOK_SET(v)		HFA384x_TX_SET(v, HFA384x_TX_TXOK, 1)
/*--------------------------------------------------------------------
Communication Frames: Receive Frames
--------------------------------------------------------------------*/
/*-- Communication Frame: Receive Frame Structure --*/
typedef struct hfa384x_rx_frame
{
	/*-- MAC rx descriptor (hfa384x byte order) --*/
	uint16_t	status;
	uint32_t	time;
	uint8_t	silence;
	uint8_t	signal;
	uint8_t	rate;
	uint8_t	rx_flow;
	uint16_t	reserved1;
	uint16_t	reserved2;

	/*-- 802.11 Header Information (802.11 byte order) --*/
	uint16_t	frame_control;
	uint16_t	duration_id;
	uint8_t	address1[6];
	uint8_t	address2[6];
	uint8_t	address3[6];
	uint16_t	sequence_control;
	uint8_t	address4[6];
	uint16_t	data_len; /* hfa384x (little endian) format */

	/*-- 802.3 Header Information --*/
	uint8_t	dest_addr[6];
	uint8_t	src_addr[6];
	uint16_t	data_length; /* IEEE? (big endian) format */
} __WLAN_ATTRIB_PACK__ hfa384x_rx_frame_t;
/*--------------------------------------------------------------------
Communication Frames: Field Masks for Receive Frames
--------------------------------------------------------------------*/
/*-- Offsets --------*/
#define		HFA384x_RX_DATA_LEN_OFF			((uint16_t)44)
#define		HFA384x_RX_80211HDR_OFF			((uint16_t)14)
#define		HFA384x_RX_DATA_OFF			((uint16_t)60)

/*-- Status Fields --*/
#define		HFA384x_RXSTATUS_MSGTYPE		((uint16_t)(BIT15 | BIT14 | BIT13))
#define		HFA384x_RXSTATUS_MACPORT		((uint16_t)(BIT10 | BIT9 | BIT8))
#define		HFA384x_RXSTATUS_UNDECR			((uint16_t)BIT1)
#define		HFA384x_RXSTATUS_FCSERR			((uint16_t)BIT0)
/*--------------------------------------------------------------------
Communication Frames: Test/Get/Set Field Values for Receive Frames
--------------------------------------------------------------------*/
#define		HFA384x_RXSTATUS_MSGTYPE_GET(value)	((uint16_t)((((uint16_t)(value)) & HFA384x_RXSTATUS_MSGTYPE) >> 13))
#define		HFA384x_RXSTATUS_MSGTYPE_SET(value)	((uint16_t)(((uint16_t)(value)) << 13))
#define		HFA384x_RXSTATUS_MACPORT_GET(value)	((uint16_t)((((uint16_t)(value)) & HFA384x_RXSTATUS_MACPORT) >> 8))
#define		HFA384x_RXSTATUS_MACPORT_SET(value)	((uint16_t)(((uint16_t)(value)) << 8))
#define		HFA384x_RXSTATUS_ISUNDECR(value)	((uint16_t)(((uint16_t)(value)) & HFA384x_RXSTATUS_UNDECR))
#define		HFA384x_RXSTATUS_ISFCSERR(value)	((uint16_t)(((uint16_t)(value)) & HFA384x_RXSTATUS_FCSERR))
/*--------------------------------------------------------------------
 FRAME STRUCTURES: Information Types and Information Frame Structures
----------------------------------------------------------------------
Information Types
--------------------------------------------------------------------*/
#define		HFA384x_IT_HANDOVERADDR			((uint16_t)0xF000UL)
#define		HFA384x_IT_HANDOVERDEAUTHADDRESS	((uint16_t)0xF001UL)//AP 1.3.7
#define		HFA384x_IT_COMMTALLIES			((uint16_t)0xF100UL)
#define		HFA384x_IT_SCANRESULTS			((uint16_t)0xF101UL)
#define		HFA384x_IT_CHINFORESULTS		((uint16_t)0xF102UL)
#define		HFA384x_IT_HOSTSCANRESULTS		((uint16_t)0xF103UL)
#define		HFA384x_IT_LINKSTATUS			((uint16_t)0xF200UL)
#define		HFA384x_IT_ASSOCSTATUS			((uint16_t)0xF201UL)
#define		HFA384x_IT_AUTHREQ			((uint16_t)0xF202UL)
#define		HFA384x_IT_PSUSERCNT			((uint16_t)0xF203UL)
#define		HFA384x_IT_KEYIDCHANGED			((uint16_t)0xF204UL)
#define		HFA384x_IT_ASSOCREQ    			((uint16_t)0xF205UL)
#define		HFA384x_IT_MICFAILURE  			((uint16_t)0xF206UL)

/*--------------------------------------------------------------------
Information Frames Structures
----------------------------------------------------------------------
Information Frames: Notification Frame Structures
--------------------------------------------------------------------*/
/*--  Notification Frame,MAC Mgmt: Handover Address --*/
typedef struct hfa384x_HandoverAddr
{
	uint16_t	framelen;
	uint16_t	infotype;
	uint8_t	handover_addr[WLAN_BSSID_LEN];
} __WLAN_ATTRIB_PACK__ hfa384x_HandoverAddr_t;

/*--  Inquiry Frame, Diagnose: Communication Tallies --*/
typedef struct hfa384x_CommTallies16
{
	uint16_t	txunicastframes;
	uint16_t	txmulticastframes;
	uint16_t	txfragments;
	uint16_t	txunicastoctets;
	uint16_t	txmulticastoctets;
	uint16_t	txdeferredtrans;
	uint16_t	txsingleretryframes;
	uint16_t	txmultipleretryframes;
	uint16_t	txretrylimitexceeded;
	uint16_t	txdiscards;
	uint16_t	rxunicastframes;
	uint16_t	rxmulticastframes;
	uint16_t	rxfragments;
	uint16_t	rxunicastoctets;
	uint16_t	rxmulticastoctets;
	uint16_t	rxfcserrors;
	uint16_t	rxdiscardsnobuffer;
	uint16_t	txdiscardswrongsa;
	uint16_t	rxdiscardswepundecr;
	uint16_t	rxmsginmsgfrag;
	uint16_t	rxmsginbadmsgfrag;
} __WLAN_ATTRIB_PACK__ hfa384x_CommTallies16_t;

typedef struct hfa384x_CommTallies32
{
	uint32_t	txunicastframes;
	uint32_t	txmulticastframes;
	uint32_t	txfragments;
	uint32_t	txunicastoctets;
	uint32_t	txmulticastoctets;
	uint32_t	txdeferredtrans;
	uint32_t	txsingleretryframes;
	uint32_t	txmultipleretryframes;
	uint32_t	txretrylimitexceeded;
	uint32_t	txdiscards;
	uint32_t	rxunicastframes;
	uint32_t	rxmulticastframes;
	uint32_t	rxfragments;
	uint32_t	rxunicastoctets;
	uint32_t	rxmulticastoctets;
	uint32_t	rxfcserrors;
	uint32_t	rxdiscardsnobuffer;
	uint32_t	txdiscardswrongsa;
	uint32_t	rxdiscardswepundecr;
	uint32_t	rxmsginmsgfrag;
	uint32_t	rxmsginbadmsgfrag;
} __WLAN_ATTRIB_PACK__ hfa384x_CommTallies32_t;

/*--  Inquiry Frame, Diagnose: Scan Results & Subfields--*/
typedef struct hfa384x_ScanResultSub
{
	uint16_t	chid;
	uint16_t	anl;
	uint16_t	sl;
	uint8_t	bssid[WLAN_BSSID_LEN];
	uint16_t	bcnint;
	uint16_t	capinfo;
	hfa384x_bytestr32_t	ssid;
	uint8_t	supprates[10]; /* 802.11 info element */
	uint16_t	proberesp_rate;
} __WLAN_ATTRIB_PACK__ hfa384x_ScanResultSub_t;

typedef struct hfa384x_ScanResult
{
	uint16_t	rsvd;
	uint16_t	scanreason;
	hfa384x_ScanResultSub_t
		result[HFA384x_SCANRESULT_MAX];
} __WLAN_ATTRIB_PACK__ hfa384x_ScanResult_t;

/*--  Inquiry Frame, Diagnose: ChInfo Results & Subfields--*/
typedef struct hfa384x_ChInfoResultSub
{
	uint16_t	chid;
	uint16_t	anl;
	uint16_t	pnl;
	uint16_t	active;
} __WLAN_ATTRIB_PACK__ hfa384x_ChInfoResultSub_t;

#define HFA384x_CHINFORESULT_BSSACTIVE	BIT0
#define HFA384x_CHINFORESULT_PCFACTIVE	BIT1

typedef struct hfa384x_ChInfoResult
{
	uint16_t	scanchannels;
	hfa384x_ChInfoResultSub_t
		result[HFA384x_CHINFORESULT_MAX];
} __WLAN_ATTRIB_PACK__ hfa384x_ChInfoResult_t;

/*--  Inquiry Frame, Diagnose: Host Scan Results & Subfields--*/
typedef struct hfa384x_HScanResultSub
{
	uint16_t	chid;
	uint16_t	anl;
	uint16_t	sl;
	uint8_t	bssid[WLAN_BSSID_LEN];
	uint16_t	bcnint;
	uint16_t	capinfo;
	hfa384x_bytestr32_t	ssid;
	uint8_t	supprates[10]; /* 802.11 info element */
	uint16_t	proberesp_rate;
	uint16_t	atim;
} __WLAN_ATTRIB_PACK__ hfa384x_HScanResultSub_t;

typedef struct hfa384x_HScanResult
{
	uint16_t	nresult;
	uint16_t	rsvd;
	hfa384x_HScanResultSub_t
		result[HFA384x_HSCANRESULT_MAX];
} __WLAN_ATTRIB_PACK__ hfa384x_HScanResult_t;

/*--  Unsolicited Frame, MAC Mgmt: LinkStatus --*/

#define HFA384x_LINK_NOTCONNECTED	((uint16_t)0)
#define HFA384x_LINK_CONNECTED		((uint16_t)1)
#define HFA384x_LINK_DISCONNECTED	((uint16_t)2)
#define HFA384x_LINK_AP_CHANGE		((uint16_t)3)
#define HFA384x_LINK_AP_OUTOFRANGE	((uint16_t)4)
#define HFA384x_LINK_AP_INRANGE		((uint16_t)5)
#define HFA384x_LINK_ASSOCFAIL		((uint16_t)6)

typedef struct hfa384x_LinkStatus
{
	uint16_t	linkstatus;
} __WLAN_ATTRIB_PACK__ hfa384x_LinkStatus_t;


/*--  Unsolicited Frame, MAC Mgmt: AssociationStatus (--*/

#define HFA384x_ASSOCSTATUS_STAASSOC	((uint16_t)1)
#define HFA384x_ASSOCSTATUS_REASSOC	((uint16_t)2)
#define HFA384x_ASSOCSTATUS_DISASSOC	((uint16_t)3)
#define HFA384x_ASSOCSTATUS_ASSOCFAIL	((uint16_t)4)
#define HFA384x_ASSOCSTATUS_AUTHFAIL	((uint16_t)5)

typedef struct hfa384x_AssocStatus
{
	uint16_t	assocstatus;
	uint8_t	sta_addr[WLAN_ADDR_LEN];
	/* old_ap_addr is only valid if assocstatus == 2 */
	uint8_t	old_ap_addr[WLAN_ADDR_LEN];
	uint16_t	reason;
	uint16_t	reserved;
} __WLAN_ATTRIB_PACK__ hfa384x_AssocStatus_t;

/*--  Unsolicited Frame, MAC Mgmt: AuthRequest (AP Only) --*/

typedef struct hfa384x_AuthRequest
{
	uint8_t	sta_addr[WLAN_ADDR_LEN];
	uint16_t	algorithm;
} __WLAN_ATTRIB_PACK__ hfa384x_AuthReq_t;

/*--  Unsolicited Frame, MAC Mgmt: AssocRequest (AP Only) --*/

typedef struct hfa384x_AssocRequest
{
	uint8_t	sta_addr[WLAN_ADDR_LEN];
	uint16_t	type;
	uint8_t   wpa_data[80];
} __WLAN_ATTRIB_PACK__ hfa384x_AssocReq_t;


#define HFA384x_ASSOCREQ_TYPE_ASSOC     0
#define HFA384x_ASSOCREQ_TYPE_REASSOC   1

/*--  Unsolicited Frame, MAC Mgmt: MIC Failure  (AP Only) --*/

typedef struct hfa384x_MicFailure
{
	uint8_t	sender[WLAN_ADDR_LEN];
	uint8_t	dest[WLAN_ADDR_LEN];
} __WLAN_ATTRIB_PACK__ hfa384x_MicFailure_t;

/*--  Unsolicited Frame, MAC Mgmt: PSUserCount (AP Only) --*/

typedef struct hfa384x_PSUserCount
{
	uint16_t	usercnt;
} __WLAN_ATTRIB_PACK__ hfa384x_PSUserCount_t;

typedef struct hfa384x_KeyIDChanged
{
	uint8_t	sta_addr[WLAN_ADDR_LEN];
	uint16_t	keyid;
} __WLAN_ATTRIB_PACK__ hfa384x_KeyIDChanged_t;

/*--  Collection of all Inf frames ---------------*/
typedef union hfa384x_infodata {
	hfa384x_CommTallies16_t	commtallies16;
	hfa384x_CommTallies32_t	commtallies32;
	hfa384x_ScanResult_t	scanresult;
	hfa384x_ChInfoResult_t	chinforesult;
	hfa384x_HScanResult_t	hscanresult;
	hfa384x_LinkStatus_t	linkstatus;
	hfa384x_AssocStatus_t	assocstatus;
	hfa384x_AuthReq_t	authreq;
	hfa384x_PSUserCount_t	psusercnt;
	hfa384x_KeyIDChanged_t  keyidchanged;
} __WLAN_ATTRIB_PACK__ hfa384x_infodata_t;

typedef struct hfa384x_InfFrame
{
	uint16_t			framelen;
	uint16_t			infotype;
	hfa384x_infodata_t	info;
} __WLAN_ATTRIB_PACK__ hfa384x_InfFrame_t;

#if (WLAN_HOSTIF == WLAN_USB)
/*--------------------------------------------------------------------
USB Packet structures and constants.
--------------------------------------------------------------------*/

/* Should be sent to the ctrlout endpoint */
#define HFA384x_USB_ENBULKIN	6

/* Should be sent to the bulkout endpoint */
#define HFA384x_USB_TXFRM	0
#define HFA384x_USB_CMDREQ	1
#define HFA384x_USB_WRIDREQ	2
#define HFA384x_USB_RRIDREQ	3
#define HFA384x_USB_WMEMREQ	4
#define HFA384x_USB_RMEMREQ	5

/* Received from the bulkin endpoint */
#define HFA384x_USB_ISFRM(a)	(!((a) & 0x8000))
#define HFA384x_USB_ISTXFRM(a)	(((a) & 0x9000) == 0x1000)
#define HFA384x_USB_ISRXFRM(a)	(!((a) & 0x9000))
#define HFA384x_USB_INFOFRM	0x8000
#define HFA384x_USB_CMDRESP	0x8001
#define HFA384x_USB_WRIDRESP	0x8002
#define HFA384x_USB_RRIDRESP	0x8003
#define HFA384x_USB_WMEMRESP	0x8004
#define HFA384x_USB_RMEMRESP	0x8005
#define HFA384x_USB_BUFAVAIL	0x8006
#define HFA384x_USB_ERROR	0x8007

/*------------------------------------*/
/* Request (bulk OUT) packet contents */

typedef struct hfa384x_usb_txfrm {
	hfa384x_tx_frame_t	desc;
	uint8_t			data[WLAN_DATA_MAXLEN];
} __WLAN_ATTRIB_PACK__ hfa384x_usb_txfrm_t;

typedef struct hfa384x_usb_cmdreq {
	uint16_t		type;
	uint16_t		cmd;
	uint16_t		parm0;
	uint16_t		parm1;
	uint16_t		parm2;
	uint8_t		pad[54];
} __WLAN_ATTRIB_PACK__ hfa384x_usb_cmdreq_t;

typedef struct hfa384x_usb_wridreq {
	uint16_t		type;
	uint16_t		frmlen;
	uint16_t		rid;
	uint8_t		data[HFA384x_RIDDATA_MAXLEN];
} __WLAN_ATTRIB_PACK__ hfa384x_usb_wridreq_t;

typedef struct hfa384x_usb_rridreq {
	uint16_t		type;
	uint16_t		frmlen;
	uint16_t		rid;
	uint8_t		pad[58];
} __WLAN_ATTRIB_PACK__ hfa384x_usb_rridreq_t;

typedef struct hfa384x_usb_wmemreq {
	uint16_t		type;
	uint16_t		frmlen;
	uint16_t		offset;
	uint16_t		page;
	uint8_t		data[HFA384x_USB_RWMEM_MAXLEN];
} __WLAN_ATTRIB_PACK__ hfa384x_usb_wmemreq_t;

typedef struct hfa384x_usb_rmemreq {
	uint16_t		type;
	uint16_t		frmlen;
	uint16_t		offset;
	uint16_t		page;
	uint8_t		pad[56];
} __WLAN_ATTRIB_PACK__ hfa384x_usb_rmemreq_t;

/*------------------------------------*/
/* Response (bulk IN) packet contents */

typedef struct hfa384x_usb_rxfrm {
	hfa384x_rx_frame_t	desc;
	uint8_t			data[WLAN_DATA_MAXLEN];
} __WLAN_ATTRIB_PACK__ hfa384x_usb_rxfrm_t;

typedef struct hfa384x_usb_infofrm {
	uint16_t			type;
	hfa384x_InfFrame_t	info;
} __WLAN_ATTRIB_PACK__ hfa384x_usb_infofrm_t;

typedef struct hfa384x_usb_statusresp {
	uint16_t		type;
	uint16_t		status;
	uint16_t		resp0;
	uint16_t		resp1;
	uint16_t		resp2;
} __WLAN_ATTRIB_PACK__ hfa384x_usb_cmdresp_t;

typedef hfa384x_usb_cmdresp_t hfa384x_usb_wridresp_t;

typedef struct hfa384x_usb_rridresp {
	uint16_t		type;
	uint16_t		frmlen;
	uint16_t		rid;
	uint8_t		data[HFA384x_RIDDATA_MAXLEN];
} __WLAN_ATTRIB_PACK__ hfa384x_usb_rridresp_t;

typedef hfa384x_usb_cmdresp_t hfa384x_usb_wmemresp_t;

typedef struct hfa384x_usb_rmemresp {
	uint16_t		type;
	uint16_t		frmlen;
	uint8_t		data[HFA384x_USB_RWMEM_MAXLEN];
} __WLAN_ATTRIB_PACK__ hfa384x_usb_rmemresp_t;

typedef struct hfa384x_usb_bufavail {
	uint16_t		type;
	uint16_t		frmlen;
} __WLAN_ATTRIB_PACK__ hfa384x_usb_bufavail_t;

typedef struct hfa384x_usb_error {
	uint16_t		type;
	uint16_t		errortype;
} __WLAN_ATTRIB_PACK__ hfa384x_usb_error_t;

/*----------------------------------------------------------*/
/* Unions for packaging all the known packet types together */

typedef union hfa384x_usbout {
	uint16_t			type;
	hfa384x_usb_txfrm_t	txfrm;
	hfa384x_usb_cmdreq_t	cmdreq;
	hfa384x_usb_wridreq_t	wridreq;
	hfa384x_usb_rridreq_t	rridreq;
	hfa384x_usb_wmemreq_t	wmemreq;
	hfa384x_usb_rmemreq_t	rmemreq;
} __WLAN_ATTRIB_PACK__ hfa384x_usbout_t;

typedef union hfa384x_usbin {
	uint16_t			type;
	hfa384x_usb_rxfrm_t	rxfrm;
	hfa384x_usb_txfrm_t	txfrm;
	hfa384x_usb_infofrm_t	infofrm;
	hfa384x_usb_cmdresp_t	cmdresp;
	hfa384x_usb_wridresp_t	wridresp;
	hfa384x_usb_rridresp_t	rridresp;
	hfa384x_usb_wmemresp_t	wmemresp;
	hfa384x_usb_rmemresp_t	rmemresp;
	hfa384x_usb_bufavail_t	bufavail;
	hfa384x_usb_error_t	usberror;
	uint8_t			boguspad[3000];
} __WLAN_ATTRIB_PACK__ hfa384x_usbin_t;

#endif /* WLAN_USB */

/*--------------------------------------------------------------------
PD record structures.
--------------------------------------------------------------------*/

typedef struct hfa384x_pdr_pcb_partnum
{
	uint8_t	num[8];
} __WLAN_ATTRIB_PACK__ hfa384x_pdr_pcb_partnum_t;

typedef struct hfa384x_pdr_pcb_tracenum
{
	uint8_t	num[8];
} __WLAN_ATTRIB_PACK__ hfa384x_pdr_pcb_tracenum_t;

typedef struct hfa384x_pdr_nic_serial
{
	uint8_t	num[12];
} __WLAN_ATTRIB_PACK__ hfa384x_pdr_nic_serial_t;

typedef struct hfa384x_pdr_mkk_measurements
{
	double	carrier_freq;
	double	occupied_band;
	double	power_density;
	double	tx_spur_f1;
	double	tx_spur_f2;
	double	tx_spur_f3;
	double	tx_spur_f4;
	double	tx_spur_l1;
	double	tx_spur_l2;
	double	tx_spur_l3;
	double	tx_spur_l4;
	double	rx_spur_f1;
	double	rx_spur_f2;
	double	rx_spur_l1;
	double	rx_spur_l2;
} __WLAN_ATTRIB_PACK__ hfa384x_pdr_mkk_measurements_t;

typedef struct hfa384x_pdr_nic_ramsize
{
	uint8_t	size[12]; /* units of KB */
} __WLAN_ATTRIB_PACK__ hfa384x_pdr_nic_ramsize_t;

typedef struct hfa384x_pdr_mfisuprange
{
	uint16_t	id;
	uint16_t	variant;
	uint16_t	bottom;
	uint16_t	top;
} __WLAN_ATTRIB_PACK__ hfa384x_pdr_mfisuprange_t;

typedef struct hfa384x_pdr_cfisuprange
{
	uint16_t	id;
	uint16_t	variant;
	uint16_t	bottom;
	uint16_t	top;
} __WLAN_ATTRIB_PACK__ hfa384x_pdr_cfisuprange_t;

typedef struct hfa384x_pdr_nicid
{
	uint16_t	id;
	uint16_t	variant;
	uint16_t	major;
	uint16_t	minor;
} __WLAN_ATTRIB_PACK__ hfa384x_pdr_nicid_t;


typedef struct hfa384x_pdr_refdac_measurements
{
	uint16_t	value[0];
} __WLAN_ATTRIB_PACK__ hfa384x_pdr_refdac_measurements_t;

typedef struct hfa384x_pdr_vgdac_measurements
{
	uint16_t	value[0];
} __WLAN_ATTRIB_PACK__ hfa384x_pdr_vgdac_measurements_t;

typedef struct hfa384x_pdr_level_comp_measurements
{
	uint16_t	value[0];
} __WLAN_ATTRIB_PACK__ hfa384x_pdr_level_compc_measurements_t;

typedef struct hfa384x_pdr_mac_address
{
	uint8_t	addr[6];
} __WLAN_ATTRIB_PACK__ hfa384x_pdr_mac_address_t;

typedef struct hfa384x_pdr_mkk_callname
{
	uint8_t	callname[8];
} __WLAN_ATTRIB_PACK__ hfa384x_pdr_mkk_callname_t;

typedef struct hfa384x_pdr_regdomain
{
	uint16_t	numdomains;
	uint16_t	domain[5];
} __WLAN_ATTRIB_PACK__ hfa384x_pdr_regdomain_t;

typedef struct hfa384x_pdr_allowed_channel
{
	uint16_t	ch_bitmap;
} __WLAN_ATTRIB_PACK__ hfa384x_pdr_allowed_channel_t;

typedef struct hfa384x_pdr_default_channel
{
	uint16_t	channel;
} __WLAN_ATTRIB_PACK__ hfa384x_pdr_default_channel_t;

typedef struct hfa384x_pdr_privacy_option
{
	uint16_t	available;
} __WLAN_ATTRIB_PACK__ hfa384x_pdr_privacy_option_t;

typedef struct hfa384x_pdr_temptype
{
	uint16_t	type;
} __WLAN_ATTRIB_PACK__ hfa384x_pdr_temptype_t;

typedef struct hfa384x_pdr_refdac_setup
{
	uint16_t	ch_value[14];
} __WLAN_ATTRIB_PACK__ hfa384x_pdr_refdac_setup_t;

typedef struct hfa384x_pdr_vgdac_setup
{
	uint16_t	ch_value[14];
} __WLAN_ATTRIB_PACK__ hfa384x_pdr_vgdac_setup_t;

typedef struct hfa384x_pdr_level_comp_setup
{
	uint16_t	ch_value[14];
} __WLAN_ATTRIB_PACK__ hfa384x_pdr_level_comp_setup_t;

typedef struct hfa384x_pdr_trimdac_setup
{
	uint16_t	trimidac;
	uint16_t	trimqdac;
} __WLAN_ATTRIB_PACK__ hfa384x_pdr_trimdac_setup_t;

typedef struct hfa384x_pdr_ifr_setting
{
	uint16_t	value[3];
} __WLAN_ATTRIB_PACK__ hfa384x_pdr_ifr_setting_t;

typedef struct hfa384x_pdr_rfr_setting
{
	uint16_t	value[3];
} __WLAN_ATTRIB_PACK__ hfa384x_pdr_rfr_setting_t;

typedef struct hfa384x_pdr_hfa3861_baseline
{
	uint16_t	value[50];
} __WLAN_ATTRIB_PACK__ hfa384x_pdr_hfa3861_baseline_t;

typedef struct hfa384x_pdr_hfa3861_shadow
{
	uint32_t	value[32];
} __WLAN_ATTRIB_PACK__ hfa384x_pdr_hfa3861_shadow_t;

typedef struct hfa384x_pdr_hfa3861_ifrf
{
	uint32_t	value[20];
} __WLAN_ATTRIB_PACK__ hfa384x_pdr_hfa3861_ifrf_t;

typedef struct hfa384x_pdr_hfa3861_chcalsp
{
	uint16_t	value[14];
} __WLAN_ATTRIB_PACK__ hfa384x_pdr_hfa3861_chcalsp_t;

typedef struct hfa384x_pdr_hfa3861_chcali
{
	uint16_t	value[17];
} __WLAN_ATTRIB_PACK__ hfa384x_pdr_hfa3861_chcali_t;

typedef struct hfa384x_pdr_hfa3861_nic_config
{
	uint16_t	config_bitmap;
} __WLAN_ATTRIB_PACK__ hfa384x_pdr_nic_config_t;

typedef struct hfa384x_pdr_hfo_delay
{
	uint8_t   hfo_delay;
} __WLAN_ATTRIB_PACK__ hfa384x_hfo_delay_t;

typedef struct hfa384x_pdr_hfa3861_manf_testsp
{
	uint16_t	value[30];
} __WLAN_ATTRIB_PACK__ hfa384x_pdr_hfa3861_manf_testsp_t;

typedef struct hfa384x_pdr_hfa3861_manf_testi
{
	uint16_t	value[30];
} __WLAN_ATTRIB_PACK__ hfa384x_pdr_hfa3861_manf_testi_t;

typedef struct hfa384x_end_of_pda
{
	uint16_t	crc;
} __WLAN_ATTRIB_PACK__ hfa384x_pdr_end_of_pda_t;

typedef struct hfa384x_pdrec
{
	uint16_t	len; /* in words */
	uint16_t	code;
	union pdr {
	hfa384x_pdr_pcb_partnum_t	pcb_partnum;
	hfa384x_pdr_pcb_tracenum_t	pcb_tracenum;
	hfa384x_pdr_nic_serial_t	nic_serial;
	hfa384x_pdr_mkk_measurements_t	mkk_measurements;
	hfa384x_pdr_nic_ramsize_t	nic_ramsize;
	hfa384x_pdr_mfisuprange_t	mfisuprange;
	hfa384x_pdr_cfisuprange_t	cfisuprange;
	hfa384x_pdr_nicid_t		nicid;
	hfa384x_pdr_refdac_measurements_t	refdac_measurements;
	hfa384x_pdr_vgdac_measurements_t	vgdac_measurements;
	hfa384x_pdr_level_compc_measurements_t	level_compc_measurements;
	hfa384x_pdr_mac_address_t	mac_address;
	hfa384x_pdr_mkk_callname_t	mkk_callname;
	hfa384x_pdr_regdomain_t		regdomain;
	hfa384x_pdr_allowed_channel_t	allowed_channel;
	hfa384x_pdr_default_channel_t	default_channel;
	hfa384x_pdr_privacy_option_t	privacy_option;
	hfa384x_pdr_temptype_t		temptype;
	hfa384x_pdr_refdac_setup_t	refdac_setup;
	hfa384x_pdr_vgdac_setup_t	vgdac_setup;
	hfa384x_pdr_level_comp_setup_t	level_comp_setup;
	hfa384x_pdr_trimdac_setup_t	trimdac_setup;
	hfa384x_pdr_ifr_setting_t	ifr_setting;
	hfa384x_pdr_rfr_setting_t	rfr_setting;
	hfa384x_pdr_hfa3861_baseline_t	hfa3861_baseline;
	hfa384x_pdr_hfa3861_shadow_t	hfa3861_shadow;
	hfa384x_pdr_hfa3861_ifrf_t	hfa3861_ifrf;
	hfa384x_pdr_hfa3861_chcalsp_t	hfa3861_chcalsp;
	hfa384x_pdr_hfa3861_chcali_t	hfa3861_chcali;
	hfa384x_pdr_nic_config_t	nic_config;
	hfa384x_hfo_delay_t             hfo_delay;
	hfa384x_pdr_hfa3861_manf_testsp_t	hfa3861_manf_testsp;
	hfa384x_pdr_hfa3861_manf_testi_t	hfa3861_manf_testi;
	hfa384x_pdr_end_of_pda_t	end_of_pda;

	} data;
} __WLAN_ATTRIB_PACK__ hfa384x_pdrec_t;


#ifdef __KERNEL__
/*--------------------------------------------------------------------
---  MAC state structure, argument to all functions --
---  Also, a collection of support types --
--------------------------------------------------------------------*/
typedef struct hfa384x_statusresult
{
	uint16_t	status;
	uint16_t	resp0;
	uint16_t	resp1;
	uint16_t	resp2;
} hfa384x_cmdresult_t;

#if (WLAN_HOSTIF == WLAN_USB)

/* USB Control Exchange (CTLX):
 *  A queue of the structure below is maintained for all of the
 *  Request/Response type USB packets supported by Prism2.
 */
/* The following hfa384x_* structures are arguments to
 * the usercb() for the different CTLX types.
 */
typedef hfa384x_cmdresult_t hfa384x_wridresult_t;
typedef hfa384x_cmdresult_t hfa384x_wmemresult_t;

typedef struct hfa384x_rridresult
{
	uint16_t		rid;
	const void	*riddata;
	unsigned int		riddata_len;
} hfa384x_rridresult_t;

enum ctlx_state {
	CTLX_START = 0,	/* Start state, not queued */

	CTLX_COMPLETE,	/* CTLX successfully completed */
	CTLX_REQ_FAILED,	/* OUT URB completed w/ error */

	CTLX_PENDING,		/* Queued, data valid */
	CTLX_REQ_SUBMITTED,	/* OUT URB submitted */
	CTLX_REQ_COMPLETE,	/* OUT URB complete */
	CTLX_RESP_COMPLETE	/* IN URB received */
};
typedef enum ctlx_state  CTLX_STATE;

struct hfa384x_usbctlx;
struct hfa384x;

typedef void (*ctlx_cmdcb_t)( struct hfa384x*, const struct hfa384x_usbctlx* );

typedef void (*ctlx_usercb_t)(
	struct hfa384x	*hw,
	void		*ctlxresult,
	void		*usercb_data);

typedef struct hfa384x_usbctlx
{
	struct list_head	list;

	size_t			outbufsize;
	hfa384x_usbout_t	outbuf;		/* pkt buf for OUT */
	hfa384x_usbin_t		inbuf;		/* pkt buf for IN(a copy) */

	CTLX_STATE		state;		/* Tracks running state */

	struct completion	done;
	volatile int		reapable;	/* Food for the reaper task */

	ctlx_cmdcb_t		cmdcb;		/* Async command callback */
	ctlx_usercb_t		usercb;		/* Async user callback, */
	void			*usercb_data;	/*  at CTLX completion  */

	int			variant;	/* Identifies cmd variant */
} hfa384x_usbctlx_t;

typedef struct hfa384x_usbctlxq
{
	spinlock_t		lock;
	struct list_head	pending;
	struct list_head	active;
	struct list_head	completing;
	struct list_head	reapable;
} hfa384x_usbctlxq_t;
#endif

typedef struct hfa484x_metacmd
{
	uint16_t		cmd;

	uint16_t          parm0;
	uint16_t          parm1;
	uint16_t          parm2;

#if 0 //XXX cmd irq stuff
	uint16_t          bulkid;         /* what RID/FID to copy down. */
	int             bulklen;        /* how much to copy from BAP */
        char            *bulkdata;      /* And to where? */
#endif

	hfa384x_cmdresult_t result;
} hfa384x_metacmd_t;

#define	MAX_PRISM2_GRP_ADDR	16
#define	MAX_GRP_ADDR		32
#define WLAN_COMMENT_MAX	80  /* Max. length of user comment string. */

#define MM_SAT_PCF		(BIT14)
#define MM_GCSD_PCF		(BIT15)
#define MM_GCSD_PCF_EB		(BIT14 | BIT15)

#define WLAN_STATE_STOPPED	0   /* Network is not active. */
#define WLAN_STATE_STARTED	1   /* Network has been started. */

#define WLAN_AUTH_MAX           60  /* Max. # of authenticated stations. */
#define WLAN_ACCESS_MAX		60  /* Max. # of stations in an access list. */
#define WLAN_ACCESS_NONE	0   /* No stations may be authenticated. */
#define WLAN_ACCESS_ALL		1   /* All stations may be authenticated. */
#define WLAN_ACCESS_ALLOW	2   /* Authenticate only "allowed" stations. */
#define WLAN_ACCESS_DENY	3   /* Do not authenticate "denied" stations. */

/* XXX These are going away ASAP */
typedef struct prism2sta_authlist
{
	unsigned int	cnt;
	uint8_t	addr[WLAN_AUTH_MAX][WLAN_ADDR_LEN];
	uint8_t	assoc[WLAN_AUTH_MAX];
} prism2sta_authlist_t;

typedef struct prism2sta_accesslist
{
	unsigned int	modify;
	unsigned int	cnt;
	uint8_t	addr[WLAN_ACCESS_MAX][WLAN_ADDR_LEN];
	unsigned int	cnt1;
	uint8_t	addr1[WLAN_ACCESS_MAX][WLAN_ADDR_LEN];
} prism2sta_accesslist_t;

typedef struct hfa384x
{
#if (WLAN_HOSTIF != WLAN_USB)
	/* Resource config */
	uint32_t			iobase;
	char			__iomem *membase;
	uint32_t			irq;
#else
	/* USB support data */
	struct usb_device	*usb;
	struct urb		rx_urb;
	struct sk_buff		*rx_urb_skb;
	struct urb		tx_urb;
	struct urb		ctlx_urb;
	hfa384x_usbout_t	txbuff;
	hfa384x_usbctlxq_t	ctlxq;
	struct timer_list	reqtimer;
	struct timer_list	resptimer;

	struct timer_list	throttle;

	struct tasklet_struct	reaper_bh;
	struct tasklet_struct	completion_bh;

	struct work_struct	usb_work;

	unsigned long		usb_flags;
#define THROTTLE_RX	0
#define THROTTLE_TX	1
#define WORK_RX_HALT	2
#define WORK_TX_HALT	3
#define WORK_RX_RESUME	4
#define WORK_TX_RESUME	5

	unsigned short		req_timer_done:1;
	unsigned short		resp_timer_done:1;

	int                     endp_in;
	int                     endp_out;
#endif /* !USB */

#if (WLAN_HOSTIF == WLAN_PCMCIA)
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,16)
	struct pcmcia_device *pdev;
#else
	dev_link_t	*link;
#endif
	dev_node_t	node;
#endif

	int                     sniff_fcs;
	int                     sniff_channel;
	int                     sniff_truncate;
	int                     sniffhdr;

	wait_queue_head_t cmdq;	        /* wait queue itself */

	/* Controller state */
	uint32_t		state;
	uint32_t		isap;
	uint8_t		port_enabled[HFA384x_NUMPORTS_MAX];
#if (WLAN_HOSTIF != WLAN_USB)
	unsigned int		auxen;
	unsigned int            isram16;
#endif /* !USB */

	/* Download support */
	unsigned int				dlstate;
	hfa384x_downloadbuffer_t	bufinfo;
	uint16_t				dltimeout;

#if (WLAN_HOSTIF != WLAN_USB)
	spinlock_t	cmdlock;
	volatile int    cmdflag;        /* wait queue flag */
	hfa384x_metacmd_t *cmddata;      /* for our async callback */

	/* BAP support */
	spinlock_t	baplock;
	struct tasklet_struct   bap_tasklet;

	/* MAC buffer ids */
        uint16_t          txfid_head;
        uint16_t          txfid_tail;
        unsigned int            txfid_N;
        uint16_t          txfid_queue[HFA384x_DRVR_FIDSTACKLEN_MAX];
	uint16_t			infofid;
	struct semaphore	infofid_sem;
#endif /* !USB */

	int                          scanflag;    /* to signal scan comlete */
	int                          join_ap;        /* are we joined to a specific ap */
	int                          join_retries;   /* number of join retries till we fail */
	hfa384x_JoinRequest_data_t   joinreq;        /* join request saved data */

	wlandevice_t            *wlandev;
	/* Timer to allow for the deferred processing of linkstatus messages */
	struct work_struct 	link_bh;

        struct work_struct      commsqual_bh;
	hfa384x_commsquality_t  qual;
	struct timer_list	commsqual_timer;

	uint16_t link_status;
	uint16_t link_status_new;
	struct sk_buff_head        authq;

	/* And here we have stuff that used to be in priv */

	/* State variables */
	unsigned int		presniff_port_type;
	uint16_t		presniff_wepflags;
	uint32_t		dot11_desired_bss_type;
	int		ap;	/* AP flag: 0 - Station, 1 - Access Point. */

	int             dbmadjust;

	/* Group Addresses - right now, there are up to a total
	of MAX_GRP_ADDR group addresses */
	uint8_t		dot11_grp_addr[MAX_GRP_ADDR][WLAN_ADDR_LEN];
	unsigned int		dot11_grpcnt;

	/* Component Identities */
	hfa384x_compident_t	ident_nic;
	hfa384x_compident_t	ident_pri_fw;
	hfa384x_compident_t	ident_sta_fw;
	hfa384x_compident_t	ident_ap_fw;
	uint16_t			mm_mods;

	/* Supplier compatibility ranges */
	hfa384x_caplevel_t	cap_sup_mfi;
	hfa384x_caplevel_t	cap_sup_cfi;
	hfa384x_caplevel_t	cap_sup_pri;
	hfa384x_caplevel_t	cap_sup_sta;
	hfa384x_caplevel_t	cap_sup_ap;

	/* Actor compatibility ranges */
	hfa384x_caplevel_t	cap_act_pri_cfi; /* pri f/w to controller interface */
	hfa384x_caplevel_t	cap_act_sta_cfi; /* sta f/w to controller interface */
	hfa384x_caplevel_t	cap_act_sta_mfi; /* sta f/w to modem interface */
	hfa384x_caplevel_t	cap_act_ap_cfi;  /* ap f/w to controller interface */
	hfa384x_caplevel_t	cap_act_ap_mfi;  /* ap f/w to modem interface */

	uint32_t			psusercount;  /* Power save user count. */
	hfa384x_CommTallies32_t	tallies;      /* Communication tallies. */
	uint8_t			comment[WLAN_COMMENT_MAX+1]; /* User comment */

	/* Channel Info request results (AP only) */
	struct {
		atomic_t		done;
		uint8_t			count;
		hfa384x_ChInfoResult_t	results;
	} channel_info;

	hfa384x_InfFrame_t      *scanresults;


        prism2sta_authlist_t	authlist;     /* Authenticated station list. */
	unsigned int			accessmode;   /* Access mode. */
        prism2sta_accesslist_t	allow;        /* Allowed station list. */
        prism2sta_accesslist_t	deny;         /* Denied station list. */

} hfa384x_t;

/*=============================================================*/
/*--- Function Declarations -----------------------------------*/
/*=============================================================*/
#if (WLAN_HOSTIF == WLAN_USB)
void
hfa384x_create(
	hfa384x_t *hw,
	struct usb_device *usb);
#else
void
hfa384x_create(
	hfa384x_t *hw,
	unsigned int irq,
	uint32_t iobase,
	uint8_t __iomem *membase);
#endif

void hfa384x_destroy(hfa384x_t *hw);

irqreturn_t
hfa384x_INTerrupt(int irq, void *dev_id PT_REGS);
int
hfa384x_corereset( hfa384x_t *hw, int holdtime, int settletime, int genesis);
int
hfa384x_drvr_chinforesults( hfa384x_t *hw);
int
hfa384x_drvr_commtallies( hfa384x_t *hw);
int
hfa384x_drvr_disable(hfa384x_t *hw, uint16_t macport);
int
hfa384x_drvr_enable(hfa384x_t *hw, uint16_t macport);
int
hfa384x_drvr_flashdl_enable(hfa384x_t *hw);
int
hfa384x_drvr_flashdl_disable(hfa384x_t *hw);
int
hfa384x_drvr_flashdl_write(hfa384x_t *hw, uint32_t daddr, void* buf, uint32_t len);
int
hfa384x_drvr_getconfig(hfa384x_t *hw, uint16_t rid, void *buf, uint16_t len);
int
hfa384x_drvr_handover( hfa384x_t *hw, uint8_t *addr);
int
hfa384x_drvr_hostscanresults( hfa384x_t *hw);
int
hfa384x_drvr_low_level(hfa384x_t *hw, hfa384x_metacmd_t *cmd);
int
hfa384x_drvr_mmi_read(hfa384x_t *hw, uint32_t address, uint32_t *result);
int
hfa384x_drvr_mmi_write(hfa384x_t *hw, uint32_t address, uint32_t data);
int
hfa384x_drvr_ramdl_enable(hfa384x_t *hw, uint32_t exeaddr);
int
hfa384x_drvr_ramdl_disable(hfa384x_t *hw);
int
hfa384x_drvr_ramdl_write(hfa384x_t *hw, uint32_t daddr, void* buf, uint32_t len);
int
hfa384x_drvr_readpda(hfa384x_t *hw, void *buf, unsigned int len);
int
hfa384x_drvr_scanresults( hfa384x_t *hw);

int
hfa384x_drvr_setconfig(hfa384x_t *hw, uint16_t rid, void *buf, uint16_t len);

static inline int
hfa384x_drvr_getconfig16(hfa384x_t *hw, uint16_t rid, void *val)
{
	int		result = 0;
	result = hfa384x_drvr_getconfig(hw, rid, val, sizeof(uint16_t));
	if ( result == 0 ) {
		*((uint16_t*)val) = hfa384x2host_16(*((uint16_t*)val));
	}
	return result;
}

static inline int
hfa384x_drvr_getconfig32(hfa384x_t *hw, uint16_t rid, void *val)
{
	int		result = 0;

	result = hfa384x_drvr_getconfig(hw, rid, val, sizeof(uint32_t));
	if ( result == 0 ) {
		*((uint32_t*)val) = hfa384x2host_32(*((uint32_t*)val));
	}

	return result;
}

static inline int
hfa384x_drvr_setconfig16(hfa384x_t *hw, uint16_t rid, uint16_t val)
{
	uint16_t value = host2hfa384x_16(val);
	return hfa384x_drvr_setconfig(hw, rid, &value, sizeof(value));
}

static inline int
hfa384x_drvr_setconfig32(hfa384x_t *hw, uint16_t rid, uint32_t val)
{
	uint32_t value = host2hfa384x_32(val);
	return hfa384x_drvr_setconfig(hw, rid, &value, sizeof(value));
}

#if (WLAN_HOSTIF == WLAN_USB)
int
hfa384x_drvr_getconfig_async(hfa384x_t     *hw,
                              uint16_t        rid,
                              ctlx_usercb_t usercb,
                              void          *usercb_data);

int
hfa384x_drvr_setconfig_async(hfa384x_t *hw,
                              uint16_t rid,
                              void *buf,
                              uint16_t len,
                              ctlx_usercb_t usercb,
                              void *usercb_data);
#else
static inline int
hfa384x_drvr_setconfig_async(hfa384x_t *hw, uint16_t rid, void *buf, uint16_t len,
			     void *ptr1, void *ptr2)
{
         (void)ptr1;
         (void)ptr2;
         return hfa384x_drvr_setconfig(hw, rid, buf, len);
}
#endif

static inline int
hfa384x_drvr_setconfig16_async(hfa384x_t *hw, uint16_t rid, uint16_t val)
{
	uint16_t value = host2hfa384x_16(val);
	return hfa384x_drvr_setconfig_async(hw, rid, &value, sizeof(value),
					    NULL , NULL);
}

static inline int
hfa384x_drvr_setconfig32_async(hfa384x_t *hw, uint16_t rid, uint32_t val)
{
	uint32_t value = host2hfa384x_32(val);
	return hfa384x_drvr_setconfig_async(hw, rid, &value, sizeof(value),
					    NULL , NULL);
}


int
hfa384x_drvr_start(hfa384x_t *hw);
int
hfa384x_drvr_stop(hfa384x_t *hw);
int
hfa384x_drvr_txframe(hfa384x_t *hw, struct sk_buff *skb, p80211_hdr_t *p80211_hdr, p80211_metawep_t *p80211_wep);
void
hfa384x_tx_timeout(wlandevice_t *wlandev);

int
hfa384x_cmd_initialize(hfa384x_t *hw);
int
hfa384x_cmd_enable(hfa384x_t *hw, uint16_t macport);
int
hfa384x_cmd_disable(hfa384x_t *hw, uint16_t macport);
int
hfa384x_cmd_diagnose(hfa384x_t *hw);
int
hfa384x_cmd_allocate(hfa384x_t *hw, uint16_t len);
int
hfa384x_cmd_transmit(hfa384x_t *hw, uint16_t reclaim, uint16_t qos, uint16_t fid);
int
hfa384x_cmd_clearpersist(hfa384x_t *hw, uint16_t fid);
int
hfa384x_cmd_notify(hfa384x_t *hw, uint16_t reclaim, uint16_t fid, void *buf, uint16_t len);
int
hfa384x_cmd_inquire(hfa384x_t *hw, uint16_t fid);
int
hfa384x_cmd_access(hfa384x_t *hw, uint16_t write, uint16_t rid, void *buf, uint16_t len);
int
hfa384x_cmd_monitor(hfa384x_t *hw, uint16_t enable);
int
hfa384x_cmd_download(
	hfa384x_t *hw,
	uint16_t mode,
	uint16_t lowaddr,
	uint16_t highaddr,
	uint16_t codelen);
int
hfa384x_cmd_aux_enable(hfa384x_t *hw, int force);
int
hfa384x_cmd_aux_disable(hfa384x_t *hw);
int
hfa384x_copy_from_bap(
	hfa384x_t *hw,
	uint16_t	bap,
	uint16_t	id,
	uint16_t	offset,
	void	*buf,
	unsigned int	len);
int
hfa384x_copy_to_bap(
	hfa384x_t *hw,
	uint16_t	bap,
	uint16_t	id,
	uint16_t	offset,
	void	*buf,
	unsigned int	len);
void
hfa384x_copy_from_aux(
	hfa384x_t *hw,
	uint32_t	cardaddr,
	uint32_t	auxctl,
	void	*buf,
	unsigned int	len);
void
hfa384x_copy_to_aux(
	hfa384x_t *hw,
	uint32_t	cardaddr,
	uint32_t	auxctl,
	void	*buf,
	unsigned int	len);

#if (WLAN_HOSTIF != WLAN_USB)

/*
   HFA384x is a LITTLE ENDIAN part.

   the get/setreg functions implicitly byte-swap the data to LE.
   the _noswap variants do not perform a byte-swap on the data.
*/

static inline uint16_t
__hfa384x_getreg(hfa384x_t *hw, unsigned int reg);

static inline void
__hfa384x_setreg(hfa384x_t *hw, uint16_t val, unsigned int reg);

static inline uint16_t
__hfa384x_getreg_noswap(hfa384x_t *hw, unsigned int reg);

static inline void
__hfa384x_setreg_noswap(hfa384x_t *hw, uint16_t val, unsigned int reg);

#ifdef REVERSE_ENDIAN
#define hfa384x_getreg __hfa384x_getreg_noswap
#define hfa384x_setreg __hfa384x_setreg_noswap
#define hfa384x_getreg_noswap __hfa384x_getreg
#define hfa384x_setreg_noswap __hfa384x_setreg
#else
#define hfa384x_getreg __hfa384x_getreg
#define hfa384x_setreg __hfa384x_setreg
#define hfa384x_getreg_noswap __hfa384x_getreg_noswap
#define hfa384x_setreg_noswap __hfa384x_setreg_noswap
#endif

/*----------------------------------------------------------------
* hfa384x_getreg
*
* Retrieve the value of one of the MAC registers.  Done here
* because different PRISM2 MAC parts use different buses and such.
* NOTE: This function returns the value in HOST ORDER!!!!!!
*
* Arguments:
*       hw         MAC part structure
*       reg        Register identifier (offset for I/O based i/f)
*
* Returns:
*       Value from the register in HOST ORDER!!!!
----------------------------------------------------------------*/
static inline uint16_t
__hfa384x_getreg(hfa384x_t *hw, unsigned int reg)
{
/*	printk(KERN_DEBUG "Reading from 0x%0x\n", hw->membase + reg); */
#if ((WLAN_HOSTIF == WLAN_PCMCIA) || (WLAN_HOSTIF == WLAN_PLX))
	return wlan_inw_le16_to_cpu(hw->iobase+reg);
#elif (WLAN_HOSTIF == WLAN_PCI)
	return __le16_to_cpu(readw(hw->membase + reg));
#endif
}

/*----------------------------------------------------------------
* hfa384x_setreg
*
* Set the value of one of the MAC registers.  Done here
* because different PRISM2 MAC parts use different buses and such.
* NOTE: This function assumes the value is in HOST ORDER!!!!!!
*
* Arguments:
*       hw	MAC part structure
*	val	Value, in HOST ORDER!!, to put in the register
*       reg	Register identifier (offset for I/O based i/f)
*
* Returns:
*       Nothing
----------------------------------------------------------------*/
static inline void
__hfa384x_setreg(hfa384x_t *hw, uint16_t val, unsigned int reg)
{
#if ((WLAN_HOSTIF == WLAN_PCMCIA) || (WLAN_HOSTIF == WLAN_PLX))
	wlan_outw_cpu_to_le16( val, hw->iobase + reg);
	return;
#elif (WLAN_HOSTIF == WLAN_PCI)
	writew(__cpu_to_le16(val), hw->membase + reg);
	return;
#endif
}


/*----------------------------------------------------------------
* hfa384x_getreg_noswap
*
* Retrieve the value of one of the MAC registers.  Done here
* because different PRISM2 MAC parts use different buses and such.
*
* Arguments:
*       hw         MAC part structure
*       reg        Register identifier (offset for I/O based i/f)
*
* Returns:
*       Value from the register.
----------------------------------------------------------------*/
static inline uint16_t
__hfa384x_getreg_noswap(hfa384x_t *hw, unsigned int reg)
{
#if ((WLAN_HOSTIF == WLAN_PCMCIA) || (WLAN_HOSTIF == WLAN_PLX))
	return wlan_inw(hw->iobase+reg);
#elif (WLAN_HOSTIF == WLAN_PCI)
	return readw(hw->membase + reg);
#endif
}


/*----------------------------------------------------------------
* hfa384x_setreg_noswap
*
* Set the value of one of the MAC registers.  Done here
* because different PRISM2 MAC parts use different buses and such.
*
* Arguments:
*       hw	MAC part structure
*	val	Value to put in the register
*       reg	Register identifier (offset for I/O based i/f)
*
* Returns:
*       Nothing
----------------------------------------------------------------*/
static inline void
__hfa384x_setreg_noswap(hfa384x_t *hw, uint16_t val, unsigned int reg)
{
#if ((WLAN_HOSTIF == WLAN_PCMCIA) || (WLAN_HOSTIF == WLAN_PLX))
	wlan_outw( val, hw->iobase + reg);
	return;
#elif (WLAN_HOSTIF == WLAN_PCI)
	writew(val, hw->membase + reg);
	return;
#endif
}


static inline void hfa384x_events_all(hfa384x_t *hw)
{
	hfa384x_setreg(hw,
		       HFA384x_INT_NORMAL
#ifdef CMD_IRQ
		       | HFA384x_INTEN_CMD_SET(1)
#endif
		       ,
		       HFA384x_INTEN);

}

static inline void hfa384x_events_nobap(hfa384x_t *hw)
{
	hfa384x_setreg(hw,
		        (HFA384x_INT_NORMAL & ~HFA384x_INT_BAP_OP)
#ifdef CMD_IRQ
		       | HFA384x_INTEN_CMD_SET(1)
#endif
		       ,
		       HFA384x_INTEN);

}

#endif /* WLAN_HOSTIF != WLAN_USB */
#endif /* __KERNEL__ */

#endif  /* _HFA384x_H */
