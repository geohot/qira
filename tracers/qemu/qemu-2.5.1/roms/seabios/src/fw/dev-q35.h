#ifndef __DEV_Q35_H
#define __DEV_Q35_H

#include "types.h"      // u16

#define PCI_DEVICE_ID_INTEL_Q35_MCH     0x29c0
#define Q35_HOST_BRIDGE_PAM0            0x90
#define Q35_HOST_BRIDGE_SMRAM           0x9d
#define Q35_HOST_BRIDGE_PCIEXBAR        0x60
#define Q35_HOST_BRIDGE_PCIEXBAR_SIZE   (256 * 1024 * 1024)
#define Q35_HOST_BRIDGE_PCIEXBAR_ADDR   0xb0000000
#define Q35_HOST_BRIDGE_PCIEXBAREN      ((u64)1)
#define Q35_HOST_PCIE_PCI_SEGMENT       0
#define Q35_HOST_PCIE_START_BUS_NUMBER  0
#define Q35_HOST_PCIE_END_BUS_NUMBER    255

#define PCI_DEVICE_ID_INTEL_ICH9_LPC    0x2918
#define ICH9_LPC_PMBASE                 0x40
#define ICH9_LPC_PMBASE_RTE             0x1

#define ICH9_LPC_ACPI_CTRL             0x44
#define ICH9_LPC_ACPI_CTRL_ACPI_EN     0x80
#define ICH9_LPC_PIRQA_ROUT            0x60
#define ICH9_LPC_PIRQE_ROUT            0x68
#define ICH9_LPC_PIRQ_ROUT_IRQEN       0x80
#define ICH9_LPC_GEN_PMCON_1           0xa0
#define ICH9_LPC_GEN_PMCON_1_SMI_LOCK  (1 << 4)
#define ICH9_LPC_PORT_ELCR1            0x4d0
#define ICH9_LPC_PORT_ELCR2            0x4d1
#define PCI_DEVICE_ID_INTEL_ICH9_SMBUS 0x2930
#define ICH9_SMB_SMB_BASE              0x20
#define ICH9_SMB_HOSTC                 0x40
#define ICH9_SMB_HOSTC_HST_EN          0x01

#define ICH9_ACPI_ENABLE               0x2
#define ICH9_ACPI_DISABLE              0x3

/* ICH9 LPC PM I/O registers are 128 ports and 128-aligned */
#define ICH9_PMIO_GPE0_STS             0x20
#define ICH9_PMIO_GPE0_BLK_LEN         0x10
#define ICH9_PMIO_SMI_EN               0x30
#define ICH9_PMIO_SMI_EN_APMC_EN       (1 << 5)
#define ICH9_PMIO_SMI_EN_GLB_SMI_EN    (1 << 0)

/* FADT ACPI_ENABLE/ACPI_DISABLE */
#define ICH9_APM_ACPI_ENABLE           0x2
#define ICH9_APM_ACPI_DISABLE          0x3

#endif // dev-q35.h
