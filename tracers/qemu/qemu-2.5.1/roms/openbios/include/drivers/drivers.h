/*
 *   OpenBIOS driver prototypes
 *
 *   (C) 2004 Stefan Reinauer <stepan@openbios.org>
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   version 2
 *
 */
#ifndef OPENBIOS_DRIVERS_H
#define OPENBIOS_DRIVERS_H

#include "config.h"

#ifdef CONFIG_DRIVER_PCI
/* drivers/pci.c */
int ob_pci_init(void);
#endif

#if defined(CONFIG_DRIVER_PCI) || defined(CONFIG_DRIVER_ESCC)
#ifdef CONFIG_PPC
extern int is_apple(void);
extern int is_oldworld(void);
extern int is_newworld(void);
#else
static inline int is_apple(void)
{
	return 0;
}
static inline int is_oldworld(void)
{
	return 0;
}
static inline int is_newworld(void)
{
	return 0;
}
#endif
#define AAPL(_cmd)      do { if (is_apple()) _cmd; } while(0)
#define OLDWORLD(_cmd)  do { if (is_oldworld()) _cmd; } while(0)
#define NEWWORLD(_cmd)  do { if (is_newworld()) _cmd; } while(0)
#endif
#ifdef CONFIG_DRIVER_SBUS
/* drivers/sbus.c */
int ob_sbus_init(uint64_t base, int machine_id);

/* arch/sparc32/console.c */
void kbd_init(uint64_t base);
#endif
#ifdef CONFIG_DRIVER_IDE
/* drivers/ide.c */
int ob_ide_init(const char *path, uint32_t io_port0, uint32_t ctl_port0,
                uint32_t io_port1, uint32_t ctl_port1);
void ob_ide_quiesce(void);
int macio_ide_init(const char *path, uint32_t addr, int nb_channels);
#endif
#ifdef CONFIG_DRIVER_ESP
/* drivers/esp.c */
int ob_esp_init(unsigned int slot, uint64_t base, unsigned long espoffset,
                unsigned long dmaoffset);
#endif
#ifdef CONFIG_DRIVER_OBIO
/* drivers/obio.c */
int ob_obio_init(uint64_t slavio_base, unsigned long fd_offset,
                 unsigned long counter_offset, unsigned long intr_offset,
                 int intr_ncpu, unsigned long aux1_offset, unsigned long aux2_offset,
                 unsigned long mem_size);
int start_cpu(unsigned int pc, unsigned int context_ptr, unsigned int context,
              int cpu);
void ob_eccmemctl_init(uint64_t base);
void ss5_init(uint64_t base);

/* drivers/iommu.c */
void ob_init_iommu(uint64_t base);
void *dvma_alloc(int size, unsigned int *pphys);

/* drivers/sbus.c */
extern uint16_t graphic_depth;

/* drivers/obio.c */
extern volatile unsigned char *power_reg;
extern volatile unsigned int *reset_reg;
extern volatile struct sun4m_timer_regs *counter_regs;

void ob_new_obio_device(const char *name, const char *type);
unsigned long ob_reg(uint64_t base, uint64_t offset, unsigned long size, int map);
void ob_intr(int intr);

/* arch/sparc32/boot.c */
extern uint32_t kernel_image;
extern uint32_t kernel_size;
extern uint32_t qemu_cmdline;
extern uint32_t cmdline_size;
extern char boot_device;
#endif
#ifdef CONFIG_DRIVER_FLOPPY
int ob_floppy_init(const char *path, const char *dev_name,
                   unsigned long io_base, unsigned long mmio_base);
#endif
#ifdef CONFIG_DRIVER_PC_KBD
void ob_pc_kbd_init(const char *path, const char *dev_name, uint64_t base,
                    uint64_t offset, int intr);
int pc_kbd_dataready(void);
unsigned char pc_kbd_readdata(void);
#endif
#ifdef CONFIG_DRIVER_PC_SERIAL
void ob_pc_serial_init(const char *path, const char *dev_name, uint64_t base,
                       uint64_t offset, int intr);
int uart_init(int port, unsigned long speed);
int uart_charav(int port);
char uart_getchar(int port);
void uart_putchar(int c);
#endif
#ifdef CONFIG_DRIVER_ESCC
int escc_uart_init(phys_addr_t port, unsigned long speed);
int escc_uart_charav(uintptr_t port);
char escc_uart_getchar(uintptr_t port);
void escc_uart_putchar(int c);
void serial_cls(void);
#ifdef CONFIG_DRIVER_ESCC_SUN
int keyboard_dataready(void);
unsigned char keyboard_readdata(void);
#endif
#endif
int macio_get_nvram_size(void);
void macio_nvram_put(char *buf);
void macio_nvram_get(char *buf);

/* drivers/timer.c */
void setup_timers(void);

#endif /* OPENBIOS_DRIVERS_H */
