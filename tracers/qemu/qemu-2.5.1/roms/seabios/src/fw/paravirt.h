#ifndef __PV_H
#define __PV_H

#include "config.h" // CONFIG_*
#include "biosvar.h" // GET_GLOBAL

// Types of paravirtualized platforms.
#define PF_QEMU     (1<<0)
#define PF_XEN      (1<<1)
#define PF_KVM      (1<<2)

extern u32 RamSize;
extern u64 RamSizeOver4G;
extern int PlatformRunningOn;

static inline int runningOnQEMU(void) {
    return CONFIG_QEMU || (
        CONFIG_QEMU_HARDWARE && GET_GLOBAL(PlatformRunningOn) & PF_QEMU);
}
static inline int runningOnXen(void) {
    return CONFIG_XEN && GET_GLOBAL(PlatformRunningOn) & PF_XEN;
}
static inline int runningOnKVM(void) {
    return CONFIG_QEMU && GET_GLOBAL(PlatformRunningOn) & PF_KVM;
}

// Common paravirt ports.
#define PORT_SMI_CMD           0x00b2
#define PORT_SMI_STATUS        0x00b3
#define PORT_QEMU_CFG_CTL      0x0510
#define PORT_QEMU_CFG_DATA     0x0511

void qemu_preinit(void);
void qemu_platform_setup(void);
void qemu_cfg_init(void);

#endif
