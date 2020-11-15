#ifndef __DEV_PIIX_H
#define __DEV_PIIX_H

#define I440FX_PAM0               0x59
#define I440FX_SMRAM              0x72

#define PIIX_PMBASE               0x40
#define PIIX_PMREGMISC            0x80
#define PIIX_SMBHSTBASE           0x90
#define PIIX_SMBHSTCFG            0xd2
#define PIIX_DEVACTB              0x58
#define PIIX_DEVACTB_APMC_EN      (1 << 25)

#define PIIX_PORT_ELCR1           0x4d0
#define PIIX_PORT_ELCR2           0x4d1

/* ICH9 PM I/O registers */
#define PIIX_GPE0_BLK            0xafe0
#define PIIX_GPE0_BLK_LEN        4
#define PIIX_PMIO_GLBCTL         0x28
#define PIIX_PMIO_GLBCTL_SMI_EN  1

/* FADT ACPI_ENABLE/ACPI_DISABLE */
#define PIIX_ACPI_ENABLE         0xf1
#define PIIX_ACPI_DISABLE        0xf0

#define PIIX_PM_INTRRUPT         9       // irq 9

#endif // dev-piix.h
