/*
 * Definitions for RTL818x hardware
 *
 * Copyright 2007 Michael Wu <flamingice@sourmilk.net>
 * Copyright 2007 Andrea Merello <andreamrl@tiscali.it>
 *
 * Modified for iPXE, June 2009, by Joshua Oreman <oremanj@rwcr.net>
 *
 * Based on the r8187 driver, which is:
 * Copyright 2005 Andrea Merello <andreamrl@tiscali.it>, et al.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef RTL818X_H
#define RTL818X_H

#include <ipxe/spi_bit.h>
#include <ipxe/tables.h>
#include <ipxe/net80211.h>

FILE_LICENCE(GPL2_ONLY);

struct rtl818x_csr {
	u8	MAC[6];
	u8	reserved_0[2];
	u32	MAR[2];
	u8	RX_FIFO_COUNT;
	u8	reserved_1;
	u8	TX_FIFO_COUNT;
	u8	BQREQ;
	u8	reserved_2[4];
	u32	TSFT[2];
	u32	TLPDA;
	u32	TNPDA;
	u32	THPDA;
	u16	BRSR;
	u8	BSSID[6];
	u8	RESP_RATE;
	u8	EIFS;
	u8	reserved_3[1];
	u8	CMD;
#define RTL818X_CMD_TX_ENABLE		(1 << 2)
#define RTL818X_CMD_RX_ENABLE		(1 << 3)
#define RTL818X_CMD_RESET		(1 << 4)
	u8	reserved_4[4];
	u16	INT_MASK;
	u16	INT_STATUS;
#define RTL818X_INT_RX_OK		(1 <<  0)
#define RTL818X_INT_RX_ERR		(1 <<  1)
#define RTL818X_INT_TXL_OK		(1 <<  2)
#define RTL818X_INT_TXL_ERR		(1 <<  3)
#define RTL818X_INT_RX_DU		(1 <<  4)
#define RTL818X_INT_RX_FO		(1 <<  5)
#define RTL818X_INT_TXN_OK		(1 <<  6)
#define RTL818X_INT_TXN_ERR		(1 <<  7)
#define RTL818X_INT_TXH_OK		(1 <<  8)
#define RTL818X_INT_TXH_ERR		(1 <<  9)
#define RTL818X_INT_TXB_OK		(1 << 10)
#define RTL818X_INT_TXB_ERR		(1 << 11)
#define RTL818X_INT_ATIM		(1 << 12)
#define RTL818X_INT_BEACON		(1 << 13)
#define RTL818X_INT_TIME_OUT		(1 << 14)
#define RTL818X_INT_TX_FO		(1 << 15)
	u32	TX_CONF;
#define RTL818X_TX_CONF_LOOPBACK_MAC	(1 << 17)
#define RTL818X_TX_CONF_LOOPBACK_CONT	(3 << 17)
#define RTL818X_TX_CONF_NO_ICV		(1 << 19)
#define RTL818X_TX_CONF_DISCW		(1 << 20)
#define RTL818X_TX_CONF_SAT_HWPLCP	(1 << 24)
#define RTL818X_TX_CONF_R8180_ABCD	(2 << 25)
#define RTL818X_TX_CONF_R8180_F		(3 << 25)
#define RTL818X_TX_CONF_R8185_ABC	(4 << 25)
#define RTL818X_TX_CONF_R8185_D		(5 << 25)
#define RTL818X_TX_CONF_R8187vD		(5 << 25)
#define RTL818X_TX_CONF_R8187vD_B	(6 << 25)
#define RTL818X_TX_CONF_HWVER_MASK	(7 << 25)
#define RTL818X_TX_CONF_DISREQQSIZE	(1 << 28)
#define RTL818X_TX_CONF_PROBE_DTS	(1 << 29)
#define RTL818X_TX_CONF_HW_SEQNUM	(1 << 30)
#define RTL818X_TX_CONF_CW_MIN		(1 << 31)
	u32	RX_CONF;
#define RTL818X_RX_CONF_MONITOR		(1 <<  0)
#define RTL818X_RX_CONF_NICMAC		(1 <<  1)
#define RTL818X_RX_CONF_MULTICAST	(1 <<  2)
#define RTL818X_RX_CONF_BROADCAST	(1 <<  3)
#define RTL818X_RX_CONF_FCS		(1 <<  5)
#define RTL818X_RX_CONF_DATA		(1 << 18)
#define RTL818X_RX_CONF_CTRL		(1 << 19)
#define RTL818X_RX_CONF_MGMT		(1 << 20)
#define RTL818X_RX_CONF_ADDR3		(1 << 21)
#define RTL818X_RX_CONF_PM		(1 << 22)
#define RTL818X_RX_CONF_BSSID		(1 << 23)
#define RTL818X_RX_CONF_RX_AUTORESETPHY	(1 << 28)
#define RTL818X_RX_CONF_CSDM1		(1 << 29)
#define RTL818X_RX_CONF_CSDM2		(1 << 30)
#define RTL818X_RX_CONF_ONLYERLPKT	(1 << 31)
	u32	INT_TIMEOUT;
	u32	TBDA;
	u8	EEPROM_CMD;
#define RTL818X_EEPROM_CMD_READ		(1 << 0)
#define RTL818X_EEPROM_CMD_WRITE	(1 << 1)
#define RTL818X_EEPROM_CMD_CK		(1 << 2)
#define RTL818X_EEPROM_CMD_CS		(1 << 3)
#define RTL818X_EEPROM_CMD_NORMAL	(0 << 6)
#define RTL818X_EEPROM_CMD_LOAD		(1 << 6)
#define RTL818X_EEPROM_CMD_PROGRAM	(2 << 6)
#define RTL818X_EEPROM_CMD_CONFIG	(3 << 6)
	u8	CONFIG0;
	u8	CONFIG1;
	u8	CONFIG2;
#define RTL818X_CONFIG2_ANTENNA_DIV	(1 << 6)
	u32	ANAPARAM;
	u8	MSR;
#define RTL818X_MSR_NO_LINK		(0 << 2)
#define RTL818X_MSR_ADHOC		(1 << 2)
#define RTL818X_MSR_INFRA		(2 << 2)
#define RTL818X_MSR_MASTER		(3 << 2)
#define RTL818X_MSR_ENEDCA		(4 << 2)
	u8	CONFIG3;
#define RTL818X_CONFIG3_ANAPARAM_WRITE	(1 << 6)
#define RTL818X_CONFIG3_GNT_SELECT	(1 << 7)
	u8	CONFIG4;
#define RTL818X_CONFIG4_POWEROFF	(1 << 6)
#define RTL818X_CONFIG4_VCOOFF		(1 << 7)
	u8	TESTR;
	u8	reserved_9[2];
	u8	PGSELECT;
	u8	SECURITY;
	u32	ANAPARAM2;
	u8	reserved_10[12];
	u16	BEACON_INTERVAL;
	u16	ATIM_WND;
	u16	BEACON_INTERVAL_TIME;
	u16	ATIMTR_INTERVAL;
	u8	PHY_DELAY;
	u8	CARRIER_SENSE_COUNTER;
	u8	reserved_11[2];
	u8	PHY[4];
	u16	RFPinsOutput;
	u16	RFPinsEnable;
	u16	RFPinsSelect;
	u16	RFPinsInput;
	u32	RF_PARA;
	u32	RF_TIMING;
	u8	GP_ENABLE;
	u8	GPIO;
	u8	reserved_12[2];
	u32	HSSI_PARA;
	u8	reserved_13[4];
	u8	TX_AGC_CTL;
#define RTL818X_TX_AGC_CTL_PERPACKET_GAIN_SHIFT		(1 << 0)
#define RTL818X_TX_AGC_CTL_PERPACKET_ANTSEL_SHIFT	(1 << 1)
#define RTL818X_TX_AGC_CTL_FEEDBACK_ANT			(1 << 2)
	u8	TX_GAIN_CCK;
	u8	TX_GAIN_OFDM;
	u8	TX_ANTENNA;
	u8	reserved_14[16];
	u8	WPA_CONF;
	u8	reserved_15[3];
	u8	SIFS;
	u8	DIFS;
	u8	SLOT;
	u8	reserved_16[5];
	u8	CW_CONF;
#define RTL818X_CW_CONF_PERPACKET_CW_SHIFT	(1 << 0)
#define RTL818X_CW_CONF_PERPACKET_RETRY_SHIFT	(1 << 1)
	u8	CW_VAL;
	u8	RATE_FALLBACK;
#define RTL818X_RATE_FALLBACK_ENABLE	(1 << 7)
	u8	ACM_CONTROL;
	u8	reserved_17[24];
	u8	CONFIG5;
	u8	TX_DMA_POLLING;
	u8	reserved_18[2];
	u16	CWR;
	u8	RETRY_CTR;
	u8	reserved_19[3];
	u16	INT_MIG;
/* RTL818X_R8187B_*: magic numbers from ioregisters */
#define RTL818X_R8187B_B	0
#define RTL818X_R8187B_D	1
#define RTL818X_R8187B_E	2
	u32	RDSAR;
	u16	TID_AC_MAP;
	u8	reserved_20[4];
	u8	ANAPARAM3;
	u8	reserved_21[5];
	u16	FEMR;
	u8	reserved_22[4];
	u16	TALLY_CNT;
	u8	TALLY_SEL;
} __attribute__((packed));

#define MAX_RX_SIZE IEEE80211_MAX_FRAME_LEN

#define RF_PARAM_ANALOGPHY	(1 << 0)
#define RF_PARAM_ANTBDEFAULT	(1 << 1)
#define RF_PARAM_CARRIERSENSE1	(1 << 2)
#define RF_PARAM_CARRIERSENSE2	(1 << 3)

#define BB_ANTATTEN_CHAN14	0x0C
#define BB_ANTENNA_B 		0x40

#define BB_HOST_BANG 		(1 << 30)
#define BB_HOST_BANG_EN 	(1 << 2)
#define BB_HOST_BANG_CLK 	(1 << 1)
#define BB_HOST_BANG_DATA	1

#define ANAPARAM_TXDACOFF_SHIFT	27
#define ANAPARAM_PWR0_SHIFT	28
#define ANAPARAM_PWR0_MASK 	(0x07 << ANAPARAM_PWR0_SHIFT)
#define ANAPARAM_PWR1_SHIFT	20
#define ANAPARAM_PWR1_MASK	(0x7F << ANAPARAM_PWR1_SHIFT)

#define RTL818X_RX_RING_SIZE	8 /* doesn't have to be a power of 2 */
#define RTL818X_TX_RING_SIZE	8 /* nor this [but 2^n is very slightly faster] */
#define RTL818X_RING_ALIGN	256

#define RTL818X_MAX_RETRIES     4

enum rtl818x_tx_desc_flags {
	RTL818X_TX_DESC_FLAG_NO_ENC	= (1 << 15),
	RTL818X_TX_DESC_FLAG_TX_OK	= (1 << 15),
	RTL818X_TX_DESC_FLAG_SPLCP	= (1 << 16),
	RTL818X_TX_DESC_FLAG_RX_UNDER	= (1 << 16),
	RTL818X_TX_DESC_FLAG_MOREFRAG	= (1 << 17),
	RTL818X_TX_DESC_FLAG_CTS	= (1 << 18),
	RTL818X_TX_DESC_FLAG_RTS	= (1 << 23),
	RTL818X_TX_DESC_FLAG_LS		= (1 << 28),
	RTL818X_TX_DESC_FLAG_FS		= (1 << 29),
	RTL818X_TX_DESC_FLAG_DMA	= (1 << 30),
	RTL818X_TX_DESC_FLAG_OWN	= (1 << 31)
};

struct rtl818x_tx_desc {
	u32 flags;
	u16 rts_duration;
	u16 plcp_len;
	u32 tx_buf;
	u32 frame_len;
	u32 next_tx_desc;
	u8 cw;
	u8 retry_limit;
	u8 agc;
	u8 flags2;
	u32 reserved[2];
} __attribute__ ((packed));

enum rtl818x_rx_desc_flags {
	RTL818X_RX_DESC_FLAG_ICV_ERR	= (1 << 12),
	RTL818X_RX_DESC_FLAG_CRC32_ERR	= (1 << 13),
	RTL818X_RX_DESC_FLAG_PM		= (1 << 14),
	RTL818X_RX_DESC_FLAG_RX_ERR	= (1 << 15),
	RTL818X_RX_DESC_FLAG_BCAST	= (1 << 16),
	RTL818X_RX_DESC_FLAG_PAM	= (1 << 17),
	RTL818X_RX_DESC_FLAG_MCAST	= (1 << 18),
	RTL818X_RX_DESC_FLAG_QOS	= (1 << 19), /* RTL8187(B) only */
	RTL818X_RX_DESC_FLAG_TRSW	= (1 << 24), /* RTL8187(B) only */
	RTL818X_RX_DESC_FLAG_SPLCP	= (1 << 25),
	RTL818X_RX_DESC_FLAG_FOF	= (1 << 26),
	RTL818X_RX_DESC_FLAG_DMA_FAIL	= (1 << 27),
	RTL818X_RX_DESC_FLAG_LS		= (1 << 28),
	RTL818X_RX_DESC_FLAG_FS		= (1 << 29),
	RTL818X_RX_DESC_FLAG_EOR	= (1 << 30),
	RTL818X_RX_DESC_FLAG_OWN	= (1 << 31)
};

struct rtl818x_rx_desc {
	u32 flags;
	u32 flags2;
	union {
		u32 rx_buf;
		u64 tsft;
	};
} __attribute__ ((packed));

struct rtl818x_priv {
	struct rtl818x_csr *map;
	const struct rtl818x_rf_ops *rf;
	int rf_flag; /* whatever RF driver wishes to use it for */
	int hw_rate;
	int hw_rtscts_rate;

	struct spi_bit_basher spibit;
	struct spi_device eeprom;

	struct rtl818x_rx_desc *rx_ring;
	u32 rx_ring_dma;
	unsigned int rx_idx;	/* next desc to be filled by card */
	struct io_buffer *rx_buf[RTL818X_RX_RING_SIZE];

	struct rtl818x_tx_desc *tx_ring;
	u32 tx_ring_dma;
	unsigned int tx_cons;	/* next desc to be filled by card */
	unsigned int tx_prod;	/* next desc to be filled by driver */
	struct io_buffer *tx_buf[RTL818X_TX_RING_SIZE];

	struct pci_device *pdev;
	u32 rx_conf;

	u16 txpower[14];

	int r8185;
	u32 anaparam;
	u16 rfparam;
	u8 csthreshold;
};

void rtl818x_write_phy(struct net80211_device *dev, u8 addr, u32 data);
void rtl818x_set_anaparam(struct rtl818x_priv *priv, u32 anaparam);

static inline u8 rtl818x_ioread8(struct rtl818x_priv *priv __unused, u8 *addr)
{
	return inb(addr);
}

static inline u16 rtl818x_ioread16(struct rtl818x_priv *priv __unused, u16 *addr)
{
	return inw(addr);
}

static inline u32 rtl818x_ioread32(struct rtl818x_priv *priv __unused, u32 *addr)
{
	return inl(addr);
}

static inline void rtl818x_iowrite8(struct rtl818x_priv *priv __unused,
				    u8 *addr, u8 val)
{
	outb(val, addr);
}

static inline void rtl818x_iowrite16(struct rtl818x_priv *priv __unused,
				     u16 *addr, u16 val)
{
	outw(val, addr);
}

static inline void rtl818x_iowrite32(struct rtl818x_priv *priv __unused,
				     u32 *addr, u32 val)
{
	outl(val, addr);
}

#define RTL818X_RF_DRIVERS __table(struct rtl818x_rf_ops, "rtl818x_rf_drivers")
#define __rtl818x_rf_driver __table_entry(RTL818X_RF_DRIVERS, 01)

struct rtl818x_rf_ops {
	char *name;
	u8 id;			/* as identified in EEPROM */
	void (*init)(struct net80211_device *dev);
	void (*stop)(struct net80211_device *dev);
	void (*set_chan)(struct net80211_device *dev, struct net80211_channel *chan);
	void (*conf_erp)(struct net80211_device *dev); /* set based on dev->erp_flags */
};

extern int rtl818x_probe(struct pci_device *pdev );
extern void rtl818x_remove(struct pci_device *pdev);

#endif /* RTL818X_H */
