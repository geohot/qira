/*
 * <bloc.c>
 *
 * Open Hack'Ware BIOS bloc devices management
 * 
 * Copyright (c) 2004-2005 Jocelyn Mayer
 * 
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License V2
 *   as published by the Free Software Foundation
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <stdlib.h>
#include <stdio.h>
#include "bios.h"

#undef DPRINTF
#define DPRINTF(fmt, args...) do { } while (0)

struct bloc_device_t {
    int device;
    /* Hardware */
    uint32_t io_base;
    int drv;
    /* Geometry */
    int heads;
    int trks;
    int sects;
    int seclen;
    /* Position */
    int bloc;
    int vbloc;
    int vpos;
    /* Access */
    int (*init)(bloc_device_t *bd, int device);
    int (*read_sector)(bloc_device_t *bd, void *buffer, int secnum);
    int (*ioctl)(bloc_device_t *bd, int func, void *args);
    /* buffer */
    char *buffer;
    /* Private data */
    int tmp;
    void *private;
#ifdef USE_OPENFIRMWARE
    void *OF_private;
#endif
    /* Partitions */
    part_t *parts, *bparts;
    part_t *boot_part;
    int bpartnum;
    /* Chain */
    bloc_device_t *next;
};

static bloc_device_t *bd_list;
 
static int fdc_initialize (bloc_device_t *bd, int device);
static int fdc_read_sector (bloc_device_t *bd, void *buffer, int secnum);

static int ide_initialize (bloc_device_t *bd, int device);
static int ide_read_sector (bloc_device_t *bd, void *buffer, int secnum);
static int ide_reset (bloc_device_t *bd);

static int mem_initialize (bloc_device_t *bd, int device);
static int mem_read_sector (bloc_device_t *bd, void *buffer, int secnum);
static int mem_ioctl (bloc_device_t *bd, int func, void *args);

bloc_device_t *bd_open (int device)
{
    bloc_device_t *bd;
    int num;

    bd = bd_get(device);
    if (bd != NULL)
        return bd;
    bd = malloc(sizeof(bloc_device_t));
    if (bd == NULL)
        return NULL;
    bd->ioctl = NULL;
    switch (device) {
    case 'a':
        num = 0;
        bd->init = &fdc_initialize;
        bd->read_sector = &fdc_read_sector;
        break;
    case 'b':
        num = 1;
        bd->init = &fdc_initialize;
        bd->read_sector = &fdc_read_sector;
        break;
    case 'c':
        num = 0;
        bd->init = &ide_initialize;
        bd->read_sector = &ide_read_sector;
        break;
    case 'd':
        num = 1;
        bd->init = &ide_initialize;
        bd->read_sector = &ide_read_sector;
        break;
    case 'e':
        num = 2;
        bd->init = &ide_initialize;
        bd->read_sector = &ide_read_sector;
        break;
    case 'f':
        num = 3;
        bd->init = &ide_initialize;
        bd->read_sector = &ide_read_sector;
        break;
    case 'm':
        num = 0;
        bd->init = &mem_initialize;
        bd->read_sector = &mem_read_sector;
        bd->ioctl = &mem_ioctl;
        break;
    default:
        return NULL;
    }
    bd->bloc = -1;
    if ((*bd->init)(bd, num) < 0) {
        free(bd);
        return NULL;
    }
    bd->buffer = malloc(bd->seclen);
    if (bd->buffer == NULL) {
        free(bd);
        return NULL;
    }
    bd->device = device;

    return bd;
}

int bd_seek (bloc_device_t *bd, uint32_t bloc, uint32_t pos)
{
    uint32_t maxbloc;

    maxbloc = bd_maxbloc(bd);
    if (bloc > maxbloc) {
        DPRINTF("%p bloc: %d maxbloc: %d C: %d H: %d S: %d\n",
                bd, bloc, maxbloc, bd->trks, bd->heads, bd->sects);
        return -1;
    }
    bd->vbloc = bloc;
    bd->vpos = pos;
    DPRINTF("%s: %p %08x %08x %08x %08x %08x\n", __func__, bd, bloc, pos,
            bd->bloc, bd->vbloc, bd->vpos);

    return 0;
}

int bd_read (bloc_device_t *bd, void *buffer, int len)
{
    int clen, total;

    for (total = 0; len > 0; total += clen) {
        if (bd->vbloc != bd->bloc) {
            /* Do physical seek */
#if 0
            DPRINTF("Read sector %d\n", bd->vbloc);
#endif
            if ((*bd->read_sector)(bd, bd->buffer, bd->vbloc) < 0) {
                printf("Error reading bloc %d\n", bd->vbloc);
                return -1;
            }
            bd->bloc = bd->vbloc;
        }
        clen = bd->seclen - bd->vpos;
        if (clen > len)
            clen = len;
        memcpy(buffer, bd->buffer + bd->vpos, clen);
#if 0
        DPRINTF("%s: %p copy %d bytes (%08x %08x %08x) %08x %08x %08x %08x\n",
                __func__, bd, clen, bd->bloc, bd->vbloc, bd->vpos,
                ((uint32_t *)buffer)[0], ((uint32_t *)buffer)[1],
                ((uint32_t *)buffer)[2], ((uint32_t *)buffer)[3]);
#endif
        bd->vpos += clen;
        if (bd->vpos == bd->seclen) {
            bd->vbloc++;
            bd->vpos = 0;
        }
        buffer += clen;
        len -= clen;
    }

    return total;
}

int bd_write (unused bloc_device_t *bd,
              unused const void *buffer, unused int len)
{
    return -1;
}

int bd_ioctl (bloc_device_t *bd, int func, void *args)
{
    if (bd->ioctl == NULL)
        return -1;

    return (*bd->ioctl)(bd, func, args);
}

void bd_close (unused bloc_device_t *bd)
{
}

void bd_reset_all(void)
{
    bloc_device_t *bd;
    for (bd = bd_list; bd != NULL; bd = bd->next) {
        if (bd->init == &ide_initialize) {
            /* reset IDE drive because Darwin wants all IDE devices to be reset */
            ide_reset(bd);
        }
    }
}

uint32_t bd_seclen (bloc_device_t *bd)
{
    return bd->seclen;
}

uint32_t bd_maxbloc (bloc_device_t *bd)
{
    return bd_CHS2sect(bd, bd->trks, 0, 1);
}

/* XXX: to be suppressed */
void bd_set_boot_part (bloc_device_t *bd, part_t *partition, int partnum)
{
    dprintf("%s: part %p (%p) %d\n", __func__, partition, bd->boot_part, partnum);
    if (bd->boot_part == NULL) {
        bd->boot_part = partition;
        bd->bpartnum = partnum;
    }
}

part_t **_bd_parts (bloc_device_t *bd)
{
    return &bd->parts;
}

part_t **_bd_bparts (bloc_device_t *bd)
{
    return &bd->bparts;
}

void bd_set_boot_device (bloc_device_t *bd)
{
#if defined (USE_OPENFIRMWARE)
    OF_blockdev_set_boot_device(bd->OF_private, bd->bpartnum, "\\\\ofwboot");
#endif
}

part_t *bd_probe (int boot_device)
{
    char devices[] = { /*'a', 'b',*/ 'c', 'd', 'e', 'f', 'm', '\0', };
    bloc_device_t *bd, **cur;
    part_t *boot_part, *tmp;
    int i, force_raw;

    boot_part = NULL;
    /* Probe bloc devices */
    for (i = 0; devices[i] != '\0'; i++) {
        if (devices[i] == 'm' && boot_device != 'm')
            break;
        bd = bd_open(devices[i]);
        if (bd != NULL) {
            DPRINTF("New bloc device %c: %p\n", devices[i], bd);
            for (cur = &bd_list; *cur != NULL; cur = &(*cur)->next)
                continue;
            *cur = bd;
        } else {
            DPRINTF("No bloc device %c\n", devices[i]);
        }
    }
    /* Probe partitions for each bloc device found */
    for (bd = bd_list; bd != NULL; bd = bd->next) {
        dprintf("Probe partitions for device %c\n", bd->device);
        if (bd->device == 'm')
            force_raw = 1;
        else
            force_raw = 0;
        tmp = part_probe(bd, force_raw);
        if (boot_device == bd->device) {
            boot_part = tmp;
            bd_set_boot_device(bd);
        }
    }

    return boot_part;
}

bloc_device_t *bd_get (int device)
{
    bloc_device_t *cur;

    for (cur = bd_list; cur != NULL; cur = cur->next) {
        if (cur->device == device) {
            DPRINTF("%s: found device %c: %p\n", __func__, device, cur);
            return cur;
        }
    }

    return NULL;
}

void bd_put (unused bloc_device_t *bd)
{
}

void bd_sect2CHS (bloc_device_t *bd, uint32_t secnum,
                  int *cyl, int *head, int *sect)
{
    uint32_t tmp;

    tmp = secnum / bd->sects;
    *sect = secnum - (tmp * bd->sects) + 1;
    *cyl = tmp / bd->heads;
    *head = tmp - (*cyl * bd->heads);
}

uint32_t bd_CHS2sect (bloc_device_t *bd,
                      int cyl, int head, int sect)
{
    return (((cyl * bd->heads) + head) * bd->sects) + sect - 1;
}

/* Floppy driver */
#define FDC_OUT_BASE    (0x03F0)
#define FDC_DOR_PORT    (FDC_OUT_BASE + 0x0002)
#define FDC_TAPE_PORT   (FDC_OUT_BASE + 0x0003)
#define FDC_MAIN_STATUS (FDC_OUT_BASE + 0x0004)
#define FDC_WRITE_PORT  (FDC_OUT_BASE + 0x0005)
#define FDC_READ_PORT   (FDC_OUT_BASE + 0x0005)

static int fdc_read_data (uint8_t *addr, int len)
{
    uint8_t status;
    int i;

    for (i = 0; i < len; i++) {
        status = inb(FDC_MAIN_STATUS);
        if ((status & 0xD0) != 0xD0) {
#if 0
            ERROR("fdc_read_data: read data status != READ_DATA: %0x\n",
                  status);
#endif
            return -1;
        }
        addr[i] = inb(FDC_READ_PORT);
    }

    return 0;
}

static inline int fdc_write_cmd (uint8_t cmd)
{
    uint8_t status;

    status = inb(FDC_MAIN_STATUS);
    if ((status & 0xC0) != 0x80) {
#if 0
        ERROR("fdc_write_cmd: read data status != WRITE_CMD: %0x\n",
              status);
#endif
        return -1;
    }
    outb(FDC_WRITE_PORT, cmd);

    return 0;
}

static int fdc_reset (void)
{
    uint8_t dor;
    
    dor = inb(FDC_DOR_PORT);
    /* Stop motors & enter reset */
    dor &= ~0x34;
    outb(FDC_DOR_PORT, dor);
    usleep(1000);
    /* leave reset state */
    dor |= 0x04;
    outb(FDC_DOR_PORT, dor);
    usleep(1000);

    return 0;
}

static int fdc_recalibrate (int drv)
{
    uint8_t data[2];

    if (drv == 0)
        data[0] = 0;
    else
        data[0] = 1;
    if (fdc_write_cmd(0x07) < 0) {
        ERROR("fdc_recalibrate != WRITE_CMD\n");
        return -1;
    }
    if (fdc_write_cmd(data[0]) < 0) {
        ERROR("fdc_recalibrate data\n");
        return -1;
    }
    /* Wait for drive to go out of busy state */
    while ((inb(FDC_MAIN_STATUS) & 0x0F) != 0x00)
        continue;
    /* Check command status */
    if (fdc_write_cmd(0x08) < 0) {
        ERROR("fdc_recalibrate != SENSE_INTERRUPT_STATUS\n");
        return -1;
    }
    data[0] = inb(FDC_READ_PORT);
    data[1] = inb(FDC_READ_PORT);
    if (data[0] & 0xD0) {
        /* recalibrate / seek failed */
        return -1;
    }
    /* Status should be WRITE_CMD right now */
    if ((inb(FDC_MAIN_STATUS) & 0xD0) != 0x80) {
        ERROR("fdc_recalibrate status\n");
        return -1;
    }

    return 0;
}

static int fdc_start_read (int drv, uint8_t hd, uint8_t trk, uint8_t sect,
                           int mt)
{
    uint8_t fdc_cmd[9], status;
    int i;
    
    fdc_cmd[0] = 0x66;
    if (mt)
        fdc_cmd[0] |= 0x80;
    fdc_cmd[1] = 0x00;
    if (hd)
        fdc_cmd[1] |= 0x04;
    if (drv)
        fdc_cmd[1] |= 0x01;
    fdc_cmd[2] = trk;
    fdc_cmd[3] = hd;
    fdc_cmd[4] = sect;
    fdc_cmd[5] = 0x02;
    fdc_cmd[6] = 0x12;
    fdc_cmd[7] = 0x00;
    fdc_cmd[8] = 0x00;
    for (i = 0; i < (int)sizeof(fdc_cmd); i++) {
        status = inb(FDC_MAIN_STATUS);
        if ((status & 0xC0) != 0x80) {
            ERROR("fdc_start_read: write command status != WRITE_CMD: %0x\n",
                  status);
            return -1;
        }
        outb(FDC_WRITE_PORT, fdc_cmd[i]);
    }
    status = inb(FDC_MAIN_STATUS);
    if ((status & 0xD0) != 0xD0) {
        ERROR("fdc_read_sector: status != READ_DATA: %0x\n", status);
        return -1;
    }

    return 0;
}

/* FDC driver entry points */
static int fdc_initialize (bloc_device_t *bd, int device)
{
    uint8_t fifo[10];
#if 0
    uint32_t tape;
#endif
    int status;

    if (device > 1)
        return -1;
    DPRINTF("Init FDC drive %d\n", device);
    /* Manage 1.44 MB disks only, for now */
    bd->drv = device;
    bd->heads = 2;
    bd->trks = 80;
    bd->sects = 18;
    bd->seclen = 512;
    bd->tmp = -1;
    fdc_reset();
    /* Dump registers */
    if (fdc_write_cmd(0x0E) < 0) {
#if 0
        ERROR("fdc_reset: DUMP_REGISTER != WRITE_CMD\n");
#endif
        return -1;
    }
    if (fdc_read_data(fifo, 10) < 0) {
        ERROR("fdc_reset: DUMP_REGISTER data\n");
        return -1;
    }
    /* SPECIFY: be sure we're not in DMA mode */
    if (fdc_write_cmd(0x03) < 0) {
        ERROR("fdc_reset: SPECIFY != WRITE_CMD\n");
        return -1;
    }
    if (fdc_write_cmd(fifo[4]) < 0 || fdc_write_cmd(fifo[5] | 0x01)) {
        ERROR("fdc_reset: SPECIFY data\n");
        return -1;
    }
    /* Status should be WRITE_CMD right now */
    status = inb(FDC_MAIN_STATUS);
    if ((status & 0xD0) != 0x80) {
        ERROR("fdc_initialise: read data status != WRITE_CMD: %0x\n",
               status);
        return -1;
    }
    /* RECALIBRATE */
    if (fdc_recalibrate(device) < 0) {
        printf("fd%c: no floppy inserted\n", 'a' + device);
        return -1;
    }
    printf("fd%c initialized\n", 'a' + device);

    return 0;
}

static int fdc_read_sector (bloc_device_t *bd, void *buffer, int secnum)
{
    int head, cyl, sect;
    int need_restart;

#if DEBUG_BIOS > 1
    printf("Read fdc sector: %d at: %0x\n", secnum, (uint32_t)buffer);
    bd_sect2CHS(bd, secnum, &cyl, &head, &sect);
    printf("cur: %d hd: %d trk: %d sect: %d\n", bd->bloc, head, cyl, sect);
#endif
    if (secnum != bd->tmp) {
        if (fdc_reset() < 0 || fdc_recalibrate(bd->drv) < 0)
            return -1;
        need_restart = 1;
    } else {
        need_restart = 0;
    }
    bd_sect2CHS(bd, secnum, &cyl, &head, &sect);
    if (need_restart == 1 || (head == 0 && sect == 1)) {
        if (need_restart == 0) {
            /* Read the status */
            uint8_t tmp[7];

            while (fdc_read_data(tmp, 1) == 0)
                continue;
        }
#if !defined (DEBUG_BIOS)
        printf(".");
#endif
        if (fdc_start_read(bd->drv, head, cyl, sect, 1) < 0)
            return -1;
        bd->bloc = secnum;
        bd->tmp = secnum;
    }
    if (fdc_read_data(buffer, bd->seclen) < 0)
        return -1;
    bd->tmp++;

    return bd->seclen;
}

/* SCSI subset */
/* SPC: primary commands, common to all devices */
static int spc_inquiry_req (void *buffer, int maxlen)
{
    uint8_t *p;
    
    p = buffer;
    p[0] = 0x12;
    /* No page code */
    p[1] = 0x00;
    p[2] = 0x00;
    p[3] = maxlen >> 8;
    p[4] = maxlen;
    p[5] = 0x00;

    return 6;
}

static int spc_inquiry_treat (void *buffer, int len)
{
    const uint8_t *p;

    if (len < 36)
        return -1;
    p = buffer;
    if ((p[0] >> 5) != 0) {
        ERROR("Logical unit not ready\n");
        return -1;
    }

    return p[0] & 0x1F;
}

static int spc_test_unit_ready_req (void *buffer)
{
    uint8_t *p;
    
    p = buffer;
    p[0] = 0x00;
    p[1] = 0x00;
    p[2] = 0x00;
    p[3] = 0x00;
    p[4] = 0x00;
    p[5] = 0x00;

    return 6;
}

/* MMC: multimedia commands */
static int mmc_read_capacity_req (void *buffer)
{
    uint8_t *p;
    
    p = buffer;
    p[0] = 0x25;
    p[1] = 0x00;
    p[2] = 0x00;
    p[3] = 0x00;
    p[4] = 0x00;
    p[5] = 0x00;
    p[6] = 0x00;
    p[7] = 0x00;
    p[8] = 0x00;
    p[9] = 0x00;

    return 10;
}

static int mmc_read_capacity_treat (uint32_t *size, uint32_t *ssize,
                                    const void *buffer, int len)
{
    const uint8_t *p;
    
    if (len != 8)
        return -1;
    p = buffer;
    /* Only handle CDROM address mode for now */
    *size = ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) + 1;
    *ssize = ((p[4] << 24) | (p[5] << 16) | (p[6] << 8) | p[7]);

    return 0;
}

static int mmc_read12_req (void *buffer, uint32_t LBA, uint32_t size)
{
    uint8_t *p;
    
    p = buffer;
    p[0] = 0xA8;
    p[1] = 0x00;
    p[2] = LBA >> 24;
    p[3] = LBA >> 16;
    p[4] = LBA >> 8;
    p[5] = LBA;
    p[6] = size >> 24;
    p[7] = size >> 16;
    p[8] = size >> 8;
    p[9] = size;
    p[10] = 0x00;
    p[11] = 0x00;

    return 12;
}

/* IDE disk driver */
static uint32_t ide_base[2] = { 0x1F0, 0x170, };
static uint32_t ide_base2[2] = { 0x3F6, 0x376, };

typedef struct ide_ops_t {
    uint8_t (*port_read)(bloc_device_t *bd, int port);
    void (*port_write)(bloc_device_t *bd, int port, uint8_t value);
    uint32_t (*data_readl)(bloc_device_t *bd);
    void (*data_writel)(bloc_device_t *bd, uint32_t val);
    void (*control_write)(bloc_device_t *bd, uint32_t val);
    uint32_t base[4];
#ifdef USE_OPENFIRMWARE
    void *OF_private[2];
#endif
} ide_ops_t;

/* IDE ISA access */
static uint8_t ide_isa_port_read (bloc_device_t *bd, int port)
{
    return inb(bd->io_base + port);
}

static void ide_isa_port_write (bloc_device_t *bd, int port, uint8_t value)
{
    outb(bd->io_base + port, value);
}

static uint32_t ide_isa_data_readl (bloc_device_t *bd)
{
    return inl(bd->io_base);
}

static void ide_isa_data_writel (bloc_device_t *bd, uint32_t val)
{
    return outl(bd->io_base, val);
}

static void ide_isa_control_write (bloc_device_t *bd, uint32_t val)
{
    outb(bd->tmp, val);
}

static ide_ops_t ide_isa_ops = {
    &ide_isa_port_read,
    &ide_isa_port_write,
    &ide_isa_data_readl,
    &ide_isa_data_writel,
    &ide_isa_control_write,
    { 0, },
#ifdef USE_OPENFIRMWARE
    { NULL, },
#endif
};

static ide_ops_t *ide_pci_ops;

/* IDE PCI access for pc */
static uint8_t ide_pci_port_read (bloc_device_t *bd, int port)
{
    uint8_t value;
    value = inb(bd->io_base + port);
    return value;
}

static void ide_pci_port_write (bloc_device_t *bd, int port, uint8_t value)
{
    outb(bd->io_base + port, value);
}

static uint32_t ide_pci_data_readl (bloc_device_t *bd)
{
    return inl(bd->io_base);
}

static void ide_pci_data_writel (bloc_device_t *bd, uint32_t val)
{
    outl(bd->io_base, val);
}

static void ide_pci_control_write (bloc_device_t *bd, uint32_t val)
{
    outb(bd->tmp + 2, val);
}

static ide_ops_t ide_pci_pc_ops = {
    &ide_pci_port_read,
    &ide_pci_port_write,
    &ide_pci_data_readl,
    &ide_pci_data_writel,
    &ide_pci_control_write,
    { 0, },
#ifdef USE_OPENFIRMWARE
    { NULL, },
#endif
};

void ide_pci_pc_register (uint32_t io_base0, uint32_t io_base1,
                          uint32_t io_base2, uint32_t io_base3,
                          void *OF_private0, void *OF_private1)
{
    if (ide_pci_ops == NULL) {
        ide_pci_ops = malloc(sizeof(ide_ops_t));
        if (ide_pci_ops == NULL)
            return;
        memcpy(ide_pci_ops, &ide_pci_pc_ops, sizeof(ide_ops_t));
    }
    if ((io_base0 != 0 || io_base1 != 0) &&
        ide_pci_ops->base[0] == 0 && ide_pci_ops->base[2] == 0) {
        ide_pci_ops->base[0] = io_base0;
        ide_pci_ops->base[2] = io_base1;
#ifdef USE_OPENFIRMWARE
        ide_pci_ops->OF_private[0] = OF_private0;
#endif
    }
    if ((io_base2 != 0 || io_base3 != 0) &&
        ide_pci_ops->base[1] == 0 && ide_pci_ops->base[3] == 0) {
        ide_pci_ops->base[1] = io_base2;
        ide_pci_ops->base[3] = io_base3;
#ifdef USE_OPENFIRMWARE
        ide_pci_ops->OF_private[1] = OF_private1;
#endif
    }
}

/* IDE PCI access for pmac */
static uint8_t ide_pmac_port_read (bloc_device_t *bd, int port)
{
    uint32_t addr;

    if (port != 8)
        addr = bd->io_base + (port << 4);
    else
        addr = bd->io_base + 0x160;
    eieio();
    
    return *((uint8_t *)addr);
}

static void ide_pmac_port_write (bloc_device_t *bd, int port, uint8_t value)
{
    uint32_t addr;

    if (port != 8)
        addr = bd->io_base + (port << 4);
    else
        addr = bd->io_base + 0x160;
    *((uint8_t *)addr) = value;
    eieio();
}

static uint32_t ide_pmac_data_readl (bloc_device_t *bd)
{
    eieio();
    return ldswap32((uint32_t *)bd->io_base);
    //    return *((uint32_t *)bd->io_base);
}

static void ide_pmac_data_writel (bloc_device_t *bd, uint32_t val)
{
    //    *((uint32_t *)bd->io_base) = val;
    stswap32((uint32_t *)bd->io_base, val);
    eieio();
}

static void ide_pmac_control_write (bloc_device_t *bd, uint32_t val)
{
    ide_pmac_port_write(bd, 8, val);
}

static ide_ops_t ide_pmac_ops = {
    &ide_pmac_port_read,
    &ide_pmac_port_write,
    &ide_pmac_data_readl,
    &ide_pmac_data_writel,
    &ide_pmac_control_write,
    { 0, },
#ifdef USE_OPENFIRMWARE
    { NULL, },
#endif
};

void ide_pci_pmac_register (uint32_t io_base0, uint32_t io_base1,
                            unused void *OF_private)
{
    if (ide_pci_ops == NULL) {
        ide_pci_ops = malloc(sizeof(ide_ops_t));
        if (ide_pci_ops == NULL)
            return;
        memcpy(ide_pci_ops, &ide_pmac_ops, sizeof(ide_ops_t));
    }
    if (io_base0 != 0 && ide_pci_ops->base[0] == 0) {
        ide_pci_ops->base[0] = io_base0;
#ifdef USE_OPENFIRMWARE
        ide_pci_ops->OF_private[0] = OF_private;
#endif
    }
    if (io_base1 != 0 && ide_pci_ops->base[1] == 0) {
        ide_pci_ops->base[1] = io_base1;
#ifdef USE_OPENFIRMWARE
        ide_pci_ops->OF_private[1] = OF_private;
#endif
    }
}

static inline uint8_t ide_port_read (bloc_device_t *bd, int port)
{
    ide_ops_t *ops = bd->private;
    
    return ops->port_read(bd, port);
}

static inline void ide_port_write (bloc_device_t *bd, int port, uint8_t value)
{
    ide_ops_t *ops = bd->private;
    
    ops->port_write(bd, port, value);
}

static inline uint32_t ide_data_readl (bloc_device_t *bd)
{
    ide_ops_t *ops = bd->private;
    
    return ops->data_readl(bd);
}

static inline void ide_data_writel (bloc_device_t *bd, uint32_t val)
{
    ide_ops_t *ops = bd->private;
    
    return ops->data_writel(bd, val);
}

static inline void ide_control_write (bloc_device_t *bd, uint32_t val)
{
    ide_ops_t *ops = bd->private;
    
    return ops->control_write(bd, val);
}

static int ide_reset (bloc_device_t *bd)
{
    int status, is_cdrom, lcyl;

    ide_control_write(bd, 0x04);
    status = ide_port_read(bd, 0x07);
    if (status != 0x90) {
        return -1;
    }
    ide_control_write(bd, 0x00);
    if (bd->drv == 0)
        ide_port_write(bd, 0x06, 0xa0);
    else
        ide_port_write(bd, 0x06, 0xb0);

    lcyl = ide_port_read(bd, 0x04);
    switch (lcyl) {
    case 0x00:
        /* IDE drive */
        is_cdrom = 0;
        break;
    case 0x14:
        /* ATAPI device */
        is_cdrom = 1;
        break;
    default:
        return -1;
    }

    return is_cdrom;
}

static void atapi_pad_req (void *buffer, int len);
static void atapi_make_req (bloc_device_t *bd, uint32_t *buffer,
                            int maxlen);
static int atapi_read_sector (bloc_device_t *bd, void *buffer, int secnum);

static int ide_initialize (bloc_device_t *bd, int device)
{
#ifdef USE_OPENFIRMWARE
    void *OF_parent;
#endif
    const unsigned char *devname, *devtype, *alias;
    uint32_t atapi_buffer[9];
    uint32_t size;
    int status, base, is_cdrom, len, i;

    if (device > 1)
        base = 1;
    else
        base = 0;
    if (ide_pci_ops != NULL) {
        bd->private = ide_pci_ops;
        bd->io_base = ide_pci_ops->base[base];
        bd->tmp = ide_pci_ops->base[2 + base];
        if (bd->io_base == 0x00000000 || bd->io_base == 0xFFFFFFFF) {
            ERROR("No IDE drive %c\n", device);
            return -1;
        }
    } else {
        bd->private = &ide_isa_ops;
        bd->io_base = ide_base[base];
        bd->tmp = ide_base2[base];
    }
    bd->drv = device & 1;
    DPRINTF("Init IDE drive %d-%d (%d)\n", base, bd->drv, device);
    is_cdrom = ide_reset(bd);
    printf("ide%d: drive %d: ",
           (device >> 1), bd->drv);
    switch(is_cdrom) {
    case 0:
        printf("Hard Disk\n");
        devname = "disk";
        devtype = "hd";
        alias = "hd";
        break;
    case 1:
        printf("CD-ROM\n");
        devname = "cdrom";
        devtype = "cdrom";
        alias = "cd";
        break;
    default:
        printf("none\n");
        devname = NULL;
        devtype = NULL;
        alias = NULL;
        break;
    }
    if (is_cdrom < 0)
        return -1;
#ifdef USE_OPENFIRMWARE
    /* Register disk into OF tree */
    OF_parent = ide_pci_ops->OF_private[base];
    if (OF_parent != NULL) {
        bd->OF_private = OF_blockdev_register(OF_parent, bd, devtype,
                                              devname, bd->drv, alias);
    }
#endif
    /* Select drive */
    if (bd->drv == 0)
        ide_port_write(bd, 0x06, 0x40);
    else
        ide_port_write(bd, 0x06, 0x50);
    /* WIN_DEVICE_RESET */
    ide_port_write(bd, 0x07, 0x08);
    status = ide_port_read(bd, 0x07);
    if (is_cdrom) {
        if (status != 0x00) {
            ERROR("WIN_DEVICE_RESET : status %0x != 0x00 (is_cdrom: %d)\n",
                  status, is_cdrom);
            return -1;
        }
        /* TEST_UNIT_READY */
        DPRINTF("TEST_UNIT_READY\n");
        len = spc_test_unit_ready_req(&atapi_buffer);
        atapi_pad_req(&atapi_buffer, len);
        ide_port_write(bd, 0x07, 0xA0);
        status = ide_port_read(bd, 0x07);
        if (status != 0x08) {
            ERROR("ATAPI TEST_UNIT_READY : status %0x != 0x08\n", status);
            /*return -1;*/ /* fails to boot from cdrom? */
        }
        for (i = 0; i < 3; i++) {
            ide_data_writel(bd, ldswap32(&atapi_buffer[i]));
        }
        status = ide_port_read(bd, 0x07);
        if (status != 0x40) {
            ERROR("ATAPI TEST_UNIT_READY : status %0x != 0x40\n", status);
            return -1;
        }
        /* INQUIRY */
        DPRINTF("INQUIRY\n");
        len = spc_inquiry_req(&atapi_buffer, 36);
        atapi_pad_req(&atapi_buffer, len);
        atapi_make_req(bd, atapi_buffer, 36);
        status = ide_port_read(bd, 0x07);
        if (status != 0x48) {
            ERROR("ATAPI INQUIRY : status %0x != 0x48\n", status);
            return -1;
        }
        for (i = 0; i < 9; i++)
            stswap32(&atapi_buffer[i], ide_data_readl(bd));
        if (spc_inquiry_treat(&atapi_buffer, 36) != 0x05) {
            ERROR("Only ATAPI CDROMs are handled for now\n");
            return -1;
        }
        /* READ_CAPACITY */
        DPRINTF("READ_CAPACITY\n");
        len = mmc_read_capacity_req(&atapi_buffer);
        atapi_pad_req(&atapi_buffer, len);
        atapi_make_req(bd, atapi_buffer, 8);
        status = ide_port_read(bd, 0x07);
        if (status != 0x48) {
            ERROR("ATAPI READ_CAPACITY : status %0x != 0x48\n", status);
            return -1;
        }
        for (i = 0; i < 2; i++)
            stswap32(&atapi_buffer[i], ide_data_readl(bd));
        if (mmc_read_capacity_treat(&size, &bd->seclen,
                                    &atapi_buffer, 8) != 0) {
            ERROR("Error retrieving ATAPI CDROM capacity\n");
            return -1;
        }
        bd->read_sector = &atapi_read_sector;
        DPRINTF("ATAPI: size=%d ssize=%d\n", size, bd->seclen);
    } else {
        if (status != 0x41) {
            ERROR("WIN_DEVICE_RESET : status %0x != 0x41 (is_cdrom: %d)\n",
                  status, is_cdrom);
            return -1;
        }
        /* WIN_READ_NATIVE_MAX */
        ide_port_write(bd, 0x07, 0xF8);
        status = ide_port_read(bd, 0x07);
        if (status != 0x40) {
            ERROR("WIN_READ_NATIVE_MAX : status %0x != 0x40\n", status);
            return -1;
        }
        /* Retrieve parameters */
        size = (ide_port_read(bd, 0x06) & ~0xF0) << 24;
        size |= ide_port_read(bd, 0x05) << 16;
        size |= ide_port_read(bd, 0x04) << 8;
        size |= ide_port_read(bd, 0x03);
        bd->seclen = 512;
    } 
    bd->heads = 16;
    bd->sects = 64;
    bd->trks = (size + (16 * 64 - 1)) >> 10;
   
    return 0;
}

static void atapi_pad_req (void *buffer, int len)
{
    uint8_t *p;

    p = buffer;
    memset(p + len, 0, 12 - len);
}

static void atapi_make_req (bloc_device_t *bd, uint32_t *buffer,
                            int maxlen)
{
    int i;
    /* select drive */
    if (bd->drv == 0)
        ide_port_write(bd, 0x06, 0x40);
    else
        ide_port_write(bd, 0x06, 0x50);
    ide_port_write(bd, 0x04, maxlen & 0xff);
    ide_port_write(bd, 0x05, (maxlen >> 8) & 0xff);
    ide_port_write(bd, 0x07, 0xA0);
    for (i = 0; i < 3; i++)
        ide_data_writel(bd, ldswap32(&buffer[i]));
}

static int atapi_read_sector (bloc_device_t *bd, void *buffer, int secnum)
{
    uint32_t atapi_buffer[4];
    uint8_t *p;
    uint32_t status, value;
    int i, len;

    len = mmc_read12_req(atapi_buffer, secnum, 1);
    atapi_pad_req(&atapi_buffer, len);
    atapi_make_req(bd, atapi_buffer, bd->seclen);
    status = ide_port_read(bd, 0x07);
    if (status != 0x48) {
        ERROR("ATAPI READ12 : status %0x != 0x48\n", status);
        return -1;
    }
    p = buffer;
    for (i = 0; i < bd->seclen; i += 4) {
        value = ide_data_readl(bd);
        *p++ = value;
        *p++ = value >> 8;
        *p++ = value >> 16;
        *p++ = value >> 24;
    }
    status = ide_port_read(bd, 0x07);
    if (status != 0x40) {
        ERROR("ATAPI READ12 done : status %0x != 0x48\n", status);
        return -1;
    }

    return 0;
}

static int ide_read_sector (bloc_device_t *bd, void *buffer, int secnum)
{
    uint32_t value;
    uint8_t *p;
    int status;
    int i;
    
    bd->drv &= 1;
    //    printf("ide_read_sector: drv %d secnum %d buf %p\n", bd->drv, secnum, buffer);
    /* select drive & set highest bytes */
    if (bd->drv == 0)
        ide_port_write(bd, 0x06, 0x40 | (secnum >> 24));
    else
        ide_port_write(bd, 0x06, 0x50 | (secnum >> 24));
    /* Set hcyl */
    ide_port_write(bd, 0x05, secnum >> 16);
    /* Set lcyl */
    ide_port_write(bd, 0x04, secnum >> 8);
    /* Set sect */
    ide_port_write(bd, 0x03, secnum);
    /* Read 1 sector */
    ide_port_write(bd, 0x02, 1);
    /* WIN_READ */
    ide_port_write(bd, 0x07, 0x20);
    status = ide_port_read(bd, 0x07);
    //    DPRINTF("ide_read_sector: try %d\n", secnum);
    if (status != 0x58) {
        ERROR("ide_read_sector: %d status %0x != 0x58\n", secnum, status);
        return -1;
    }
    /* Get data */
    p = buffer;
    for (i = 0; i < bd->seclen; i += 4) {
        value = ide_data_readl(bd);
        *p++ = value;
        *p++ = value >> 8;
        *p++ = value >> 16;
        *p++ = value >> 24;
    }
    status = ide_port_read(bd, 0x07);
    if (status != 0x50) {
        ERROR("ide_read_sector 6: status %0x != 0x50\n", status);
        return -1;
    }

    return bd->seclen;
}

/* Memory image access driver */
static int mem_initialize (bloc_device_t *bd, int device)
{
    bd->seclen = 512;
    bd->private = NULL;
    bd->heads = 1;
    bd->sects = 1;
    bd->trks = 1;

    return device == 'm';
}

static int mem_read_sector (bloc_device_t *bd, void *buffer, int secnum)
{
    if (buffer != (char *)bd->private + (bd->seclen * secnum)) {
        memmove(buffer,
                (char *)bd->private + (bd->seclen * secnum), bd->seclen);
    }

    return bd->seclen;
}

static int mem_ioctl (bloc_device_t *bd, int func, void *args)
{
    uint32_t *u32;
    int ret;

    switch (func) {
    case MEM_SET_ADDR:
        bd->private = args;
        ret = 0;
        break;
    case MEM_SET_SIZE:
        u32 = args;
        bd->trks = (*u32 + bd->seclen - 1) / bd->seclen + 1;
    default:
        ret = -1;
        break;
    }

    return ret;
}
