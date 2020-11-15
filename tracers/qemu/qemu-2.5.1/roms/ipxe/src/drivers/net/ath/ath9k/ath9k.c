/*
 * Copyright (c) 2008-2011 Atheros Communications Inc.
 *
 * Modified for iPXE by Scott K Logan <logans@cottsay.net> July 2011
 * Original from Linux kernel 3.0.1
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <ipxe/pci.h>

#include "ath9k.h"

static struct pci_device_id ath_pci_id_table[] = {
        PCI_ROM(0x168c, 0x0023, "ar5416", "Atheros 5416 PCI", 0),	/* PCI   */
        PCI_ROM(0x168c, 0x0024, "ar5416", "Atheros 5416 PCI-E", 0),	/* PCI-E */
        PCI_ROM(0x168c, 0x0027, "ar9160", "Atheros 9160 PCI", 0),	/* PCI   */
        PCI_ROM(0x168c, 0x0029, "ar9280", "Atheros 9280 PCI", 0),	/* PCI   */
        PCI_ROM(0x168c, 0x002A, "ar9280", "Atheros 9280 PCI-E", 0),	/* PCI-E */
        PCI_ROM(0x168c, 0x002B, "ar9285", "Atheros 9285 PCI-E", 0),	/* PCI-E */
        PCI_ROM(0x168c, 0x002C, "ar2427", "Atheros 2427 PCI-E", 0),	/* PCI-E 802.11n bonded out */
        PCI_ROM(0x168c, 0x002D, "ar9287", "Atheros 9287 PCI", 0),	/* PCI   */
        PCI_ROM(0x168c, 0x002E, "ar9287", "Atheros 9287 PCI-E", 0),	/* PCI-E */
        PCI_ROM(0x168c, 0x0030, "ar9300", "Atheros 9300 PCI-E", 0),	/* PCI-E  AR9300 */
        PCI_ROM(0x168c, 0x0032, "ar9485", "Atheros 9485 PCI-E", 0),	/* PCI-E  AR9485 */
};


/* return bus cachesize in 4B word units */
static void ath_pci_read_cachesize(struct ath_common *common, int *csz)
{
	struct ath_softc *sc = (struct ath_softc *) common->priv;
	u8 u8tmp;

	pci_read_config_byte(sc->pdev, PCI_CACHE_LINE_SIZE, &u8tmp);
	*csz = (int)u8tmp;

	/*
	 * This check was put in to avoid "unpleasant" consequences if
	 * the bootrom has not fully initialized all PCI devices.
	 * Sometimes the cache line size register is not set
	 */

	if (*csz == 0)
		*csz = DEFAULT_CACHELINE >> 2;   /* Use the default size */
}

static int ath_pci_eeprom_read(struct ath_common *common, u32 off, u16 *data)
{
	struct ath_hw *ah = (struct ath_hw *) common->ah;

	common->ops->read(ah, AR5416_EEPROM_OFFSET +
			      (off << AR5416_EEPROM_S));

	if (!ath9k_hw_wait(ah,
			   AR_EEPROM_STATUS_DATA,
			   AR_EEPROM_STATUS_DATA_BUSY |
			   AR_EEPROM_STATUS_DATA_PROT_ACCESS, 0,
			   AH_WAIT_TIMEOUT)) {
		return 0;
	}

	*data = MS(common->ops->read(ah, AR_EEPROM_STATUS_DATA),
		   AR_EEPROM_STATUS_DATA_VAL);

	return 1;
}

static void ath_pci_extn_synch_enable(struct ath_common *common)
{
	struct ath_softc *sc = (struct ath_softc *) common->priv;
	struct pci_device *pdev = sc->pdev;
	u8 lnkctl;

	pci_read_config_byte(pdev, sc->sc_ah->caps.pcie_lcr_offset, &lnkctl);
	lnkctl |= 0x0080;
	pci_write_config_byte(pdev, sc->sc_ah->caps.pcie_lcr_offset, lnkctl);
}

static const struct ath_bus_ops ath_pci_bus_ops = {
	.ath_bus_type = ATH_PCI,
	.read_cachesize = ath_pci_read_cachesize,
	.eeprom_read = ath_pci_eeprom_read,
	.extn_synch_en = ath_pci_extn_synch_enable,
};

static int ath_pci_probe(struct pci_device *pdev)
{
	void *mem;
	struct ath_softc *sc;
	struct net80211_device *dev;
	u8 csz;
	u16 subsysid;
	u32 val;
	int ret = 0;
	char hw_name[64];

	adjust_pci_device(pdev);

	/*
	 * Cache line size is used to size and align various
	 * structures used to communicate with the hardware.
	 */
	pci_read_config_byte(pdev, PCI_CACHE_LINE_SIZE, &csz);
	if (csz == 0) {
		/*
		 * Linux 2.4.18 (at least) writes the cache line size
		 * register as a 16-bit wide register which is wrong.
		 * We must have this setup properly for rx buffer
		 * DMA to work so force a reasonable value here if it
		 * comes up zero.
		 */
		csz =16;
		pci_write_config_byte(pdev, PCI_CACHE_LINE_SIZE, csz);
	}
	/*
	 * The default setting of latency timer yields poor results,
	 * set it to the value used by other systems. It may be worth
	 * tweaking this setting more.
	 */
	pci_write_config_byte(pdev, PCI_LATENCY_TIMER, 0xa8);

	/*
	 * Disable the RETRY_TIMEOUT register (0x41) to keep
	 * PCI Tx retries from interfering with C3 CPU state.
	 */
	pci_read_config_dword(pdev, 0x40, &val);
	if ((val & 0x0000ff00) != 0)
		pci_write_config_dword(pdev, 0x40, val & 0xffff00ff);

	mem = ioremap(pdev->membase, 0x10000);
	if (!mem) {
		DBG("ath9K: PCI memory map error\n") ;
		ret = -EIO;
		goto err_iomap;
	}

	dev = net80211_alloc(sizeof(struct ath_softc));
	if (!dev) {
		DBG("ath9k: No memory for net80211_device\n");
		ret = -ENOMEM;
		goto err_alloc_hw;
	}

	pci_set_drvdata(pdev, dev);
	dev->netdev->dev = (struct device *)pdev;

	sc = dev->priv;
	sc->dev = dev;
	sc->pdev = pdev;
	sc->mem = mem;

	/* Will be cleared in ath9k_start() */
	sc->sc_flags |= SC_OP_INVALID;

	sc->irq = pdev->irq;

	pci_read_config_word(pdev, PCI_SUBSYSTEM_ID, &subsysid);
	ret = ath9k_init_device(pdev->device, sc, subsysid, &ath_pci_bus_ops);
	if (ret) {
		DBG("ath9k: Failed to initialize device\n");
		goto err_init;
	}

	ath9k_hw_name(sc->sc_ah, hw_name, sizeof(hw_name));
	DBG("ath9k: %s mem=0x%lx, irq=%d\n",
		   hw_name, (unsigned long)mem, pdev->irq);

	return 0;

err_init:
	net80211_free(dev);
err_alloc_hw:
	iounmap(mem);
err_iomap:
	return ret;
}

static void ath_pci_remove(struct pci_device *pdev)
{
	struct net80211_device *dev = pci_get_drvdata(pdev);
	struct ath_softc *sc = dev->priv;
	void *mem = sc->mem;

	if (!is_ath9k_unloaded)
		sc->sc_ah->ah_flags |= AH_UNPLUGGED;
	ath9k_deinit_device(sc);
	net80211_free(sc->dev);

	iounmap(mem);
}

struct pci_driver ath_pci_driver __pci_driver = {
        .id_count   = ARRAY_SIZE(ath_pci_id_table),
	.ids        = ath_pci_id_table,
	.probe      = ath_pci_probe,
	.remove     = ath_pci_remove,
};
