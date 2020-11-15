/*
 *   OpenBIOS ESP driver
 *
 *   Copyright (C) 2004 Jens Axboe <axboe@suse.de>
 *   Copyright (C) 2005 Stefan Reinauer <stepan@openbios.org>
 *
 *   Credit goes to Hale Landis for his excellent ata demo software
 *   OF node handling and some fixes by Stefan Reinauer
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   version 2
 *
 */

#include "config.h"
#include "libopenbios/bindings.h"
#include "kernel/kernel.h"
#include "libc/byteorder.h"
#include "libc/vsprintf.h"

#include "drivers/drivers.h"
#include "asm/io.h"
#include "scsi.h"
#include "asm/dma.h"
#include "esp.h"
#include "libopenbios/ofmem.h"

#define BUFSIZE         4096

#ifdef CONFIG_DEBUG_ESP
#define DPRINTF(fmt, args...)                   \
    do { printk(fmt , ##args); } while (0)
#else
#define DPRINTF(fmt, args...)
#endif

struct esp_dma {
    volatile struct sparc_dma_registers *regs;
    enum dvma_rev revision;
};

typedef struct sd_private {
    unsigned int bs;
    const char *media_str[2];
    uint32_t sectors;
    uint8_t media;
    uint8_t id;
    uint8_t present;
    char model[40];
} sd_private_t;

struct esp_regs {
    unsigned char regs[ESP_REG_SIZE];
};

typedef struct esp_private {
    volatile struct esp_regs *ll;
    uint32_t buffer_dvma;
    unsigned int irq;        /* device IRQ number    */
    struct esp_dma espdma;
    unsigned char *buffer;
    sd_private_t sd[8];
} esp_private_t;

static esp_private_t *global_esp;

/* DECLARE data structures for the nodes.  */
DECLARE_UNNAMED_NODE(ob_sd, INSTALL_OPEN, sizeof(sd_private_t *));
DECLARE_UNNAMED_NODE(ob_esp, INSTALL_OPEN, sizeof(esp_private_t *));

#ifdef CONFIG_DEBUG_ESP
static void dump_drive(sd_private_t *drive)
{
    printk("SCSI DRIVE @%lx:\n", (unsigned long)drive);
    printk("id: %d\n", drive->id);
    printk("media: %s\n", drive->media_str[0]);
    printk("media: %s\n", drive->media_str[1]);
    printk("model: %s\n", drive->model);
    printk("sectors: %d\n", drive->sectors);
    printk("present: %d\n", drive->present);
    printk("bs: %d\n", drive->bs);
}
#endif

static int
do_command(esp_private_t *esp, sd_private_t *sd, int cmdlen, int replylen)
{
    int status;

    // Set SCSI target
    esp->ll->regs[ESP_BUSID] = sd->id & 7;
    // Set DMA address
    esp->espdma.regs->st_addr = esp->buffer_dvma;
    // Set DMA length
    esp->ll->regs[ESP_TCLOW] = cmdlen & 0xff;
    esp->ll->regs[ESP_TCMED] = (cmdlen >> 8) & 0xff;
    // Set DMA direction and enable DMA
    esp->espdma.regs->cond_reg = DMA_ENABLE;
    // Set ATN, issue command
    esp->ll->regs[ESP_CMD] = ESP_CMD_SELA | ESP_CMD_DMA;
    // Wait for DMA to complete. Can this fail?
    while ((esp->espdma.regs->cond_reg & DMA_HNDL_INTR) == 0) /* no-op */;
    // Check status
    status = esp->ll->regs[ESP_STATUS];
    // Clear interrupts to avoid guests seeing spurious interrupts
    (void)esp->ll->regs[ESP_INTRPT];

    DPRINTF("do_command: id %d, cmd[0] 0x%x, status 0x%x\n", sd->id, esp->buffer[1], status);

    /* Target didn't want all command data? */
    if ((status & ESP_STAT_TCNT) != ESP_STAT_TCNT) {
        return status;
    }
    if (replylen == 0) {
        return 0;
    }
    /* Target went to status phase instead of data phase? */
    if ((status & ESP_STAT_PMASK) == ESP_STATP) {
        return status;
    }

    // Get reply
    // Set DMA address
    esp->espdma.regs->st_addr = esp->buffer_dvma;
    // Set DMA length
    esp->ll->regs[ESP_TCLOW] = replylen & 0xff;
    esp->ll->regs[ESP_TCMED] = (replylen >> 8) & 0xff;
    // Set DMA direction
    esp->espdma.regs->cond_reg = DMA_ST_WRITE | DMA_ENABLE;
    // Transfer
    esp->ll->regs[ESP_CMD] = ESP_CMD_TI | ESP_CMD_DMA;
    // Wait for DMA to complete
    while ((esp->espdma.regs->cond_reg & DMA_HNDL_INTR) == 0) /* no-op */;
    // Check status
    status = esp->ll->regs[ESP_STATUS];
    // Clear interrupts to avoid guests seeing spurious interrupts
    (void)esp->ll->regs[ESP_INTRPT];

    DPRINTF("do_command_reply: status 0x%x\n", status);

    if ((status & ESP_STAT_TCNT) != ESP_STAT_TCNT)
        return status;
    else
        return 0; // OK
}

// offset is in sectors
static int
ob_sd_read_sector(esp_private_t *esp, sd_private_t *sd, int offset)
{
    DPRINTF("ob_sd_read_sector id %d sector=%d\n",
            sd->id, offset);

    // Setup command = Read(10)
    memset(esp->buffer, 0, 11);
    esp->buffer[0] = 0x80;
    esp->buffer[1] = READ_10;

    esp->buffer[3] = (offset >> 24) & 0xff;
    esp->buffer[4] = (offset >> 16) & 0xff;
    esp->buffer[5] = (offset >> 8) & 0xff;
    esp->buffer[6] = offset & 0xff;

    esp->buffer[8] = 0;
    esp->buffer[9] = 1;

    if (do_command(esp, sd, 11, sd->bs))
        return 0;

    return 0;
}

static unsigned int
read_capacity(esp_private_t *esp, sd_private_t *sd)
{
    // Setup command = Read Capacity
    memset(esp->buffer, 0, 11);
    esp->buffer[0] = 0x80;
    esp->buffer[1] = READ_CAPACITY;

    if (do_command(esp, sd, 11, 8)) {
        sd->sectors = 0;
        sd->bs = 0;
        DPRINTF("read_capacity id %d failed\n", sd->id);
        return 0;
    }
    sd->bs = (esp->buffer[4] << 24) | (esp->buffer[5] << 16) | (esp->buffer[6] << 8) | esp->buffer[7];
    sd->sectors = ((esp->buffer[0] << 24) | (esp->buffer[1] << 16) | (esp->buffer[2] << 8) | esp->buffer[3]) * (sd->bs / 512);

    DPRINTF("read_capacity id %d bs %d sectors %d\n", sd->id, sd->bs,
            sd->sectors);
    return 1;
}

static unsigned int
test_unit_ready(esp_private_t *esp, sd_private_t *sd)
{
    /* Setup command = Test Unit Ready */
    memset(esp->buffer, 0, 7);
    esp->buffer[0] = 0x80;
    esp->buffer[1] = TEST_UNIT_READY;

    if (do_command(esp, sd, 7, 0)) {
        DPRINTF("test_unit_ready id %d failed\n", sd->id);
        return 0;
    }

    DPRINTF("test_unit_ready id %d success\n", sd->id);
    return 1;
}

static unsigned int
inquiry(esp_private_t *esp, sd_private_t *sd)
{
    const char *media[2] = { "UNKNOWN", "UNKNOWN"};

    // Setup command = Inquiry
    memset(esp->buffer, 0, 7);
    esp->buffer[0] = 0x80;
    esp->buffer[1] = INQUIRY;

    esp->buffer[5] = 36;

    if (do_command(esp, sd, 7, 36)) {
        sd->present = 0;
        sd->media = -1;
        return 0;
    }
    sd->present = 1;
    sd->media = esp->buffer[0];

    switch (sd->media) {
    case TYPE_DISK:
        media[0] = "disk";
        media[1] = "hd";
        break;
    case TYPE_ROM:
        media[0] = "cdrom";
        media[1] = "cd";
        break;
    }
    sd->media_str[0] = media[0];
    sd->media_str[1] = media[1];
    memcpy(sd->model, &esp->buffer[16], 16);
    sd->model[17] = '\0';

    return 1;
}


static void
ob_sd_read_blocks(sd_private_t **sd)
{
    cell n = POP(), cnt = n;
    ucell blk = POP();
    char *dest = (char*)POP();
    int pos, spb, sect_offset;

    DPRINTF("ob_sd_read_blocks id %d %lx block=%d n=%d\n", (*sd)->id, (unsigned long)dest, blk, n );

    if ((*sd)->bs == 0) {
        PUSH(0);
        return;
    }
    spb = (*sd)->bs / 512;
    while (n) {
        sect_offset = blk / spb;
        pos = (blk - sect_offset * spb) * 512;

        if (ob_sd_read_sector(global_esp, *sd, sect_offset)) {
            DPRINTF("ob_sd_read_blocks: error\n");
            RET(0);
        }
        while (n && pos < spb * 512) {
            memcpy(dest, global_esp->buffer + pos, 512);
            pos += 512;
            dest += 512;
            n--;
            blk++;
        }
    }
    PUSH(cnt);
}

static void
ob_sd_block_size(__attribute__((unused))sd_private_t **sd)
{
    PUSH(512);
}

static void
ob_sd_open(__attribute__((unused))sd_private_t **sd)
{
    int ret = 1, id;
    phandle_t ph;

    fword("my-unit");
    id = POP();
    POP(); // unit id is 2 ints but we only need one.
    *sd = &global_esp->sd[id];

#ifdef CONFIG_DEBUG_ESP
    {
        char *args;

        fword("my-args");
        args = pop_fstr_copy();
        DPRINTF("opening drive %d args %s\n", id, args);
        free(args);
    }
#endif

    selfword("open-deblocker");

    /* interpose disk-label */
    ph = find_dev("/packages/disk-label");
    fword("my-args");
    PUSH_ph( ph );
    fword("interpose");

    RET ( -ret );
}

static void
ob_sd_close(__attribute__((unused)) sd_private_t **sd)
{
    selfword("close-deblocker");
}

NODE_METHODS(ob_sd) = {
    { "open",           ob_sd_open },
    { "close",          ob_sd_close },
    { "read-blocks",    ob_sd_read_blocks },
    { "block-size",     ob_sd_block_size },
};


static int
espdma_init(unsigned int slot, uint64_t base, unsigned long offset,
            struct esp_dma *espdma)
{
    espdma->regs = (void *)ofmem_map_io(base + (uint64_t)offset, 0x10);

    if (espdma->regs == NULL) {
        DPRINTF("espdma_init: cannot map registers\n");
        return -1;
    }

    DPRINTF("dma1: ");

    switch ((espdma->regs->cond_reg) & DMA_DEVICE_ID) {
    case DMA_VERS0:
        espdma->revision = dvmarev0;
        DPRINTF("Revision 0 ");
        break;
    case DMA_ESCV1:
        espdma->revision = dvmaesc1;
        DPRINTF("ESC Revision 1 ");
        break;
    case DMA_VERS1:
        espdma->revision = dvmarev1;
        DPRINTF("Revision 1 ");
        break;
    case DMA_VERS2:
        espdma->revision = dvmarev2;
        DPRINTF("Revision 2 ");
        break;
    case DMA_VERHME:
        espdma->revision = dvmahme;
        DPRINTF("HME DVMA gate array ");
        break;
    case DMA_VERSPLUS:
        espdma->revision = dvmarevplus;
        DPRINTF("Revision 1 PLUS ");
        break;
    default:
        DPRINTF("unknown dma version %x",
               (espdma->regs->cond_reg) & DMA_DEVICE_ID);
        /* espdma->allocated = 1; */
        break;
    }
    DPRINTF("\n");

    push_str("/iommu/sbus/espdma");
    fword("find-device");

    /* set reg */
    PUSH(slot);
    fword("encode-int");
    PUSH(offset);
    fword("encode-int");
    fword("encode+");
    PUSH(0x00000010);
    fword("encode-int");
    fword("encode+");
    push_str("reg");
    fword("property");

    return 0;
}

static void
ob_esp_initialize(__attribute__((unused)) esp_private_t **esp)
{
    phandle_t ph = get_cur_dev();

    set_int_property(ph, "#address-cells", 2);
    set_int_property(ph, "#size-cells", 0);

    /* set device type */
    push_str("scsi");
    fword("device-type");

    /* QEMU's ESP emulation does not support mixing DMA and FIFO messages. By
       setting this attribute, we prevent the Solaris ESP kernel driver from
       trying to use this feature when booting a disk image (and failing) */
    PUSH(0x58);
    fword("encode-int");
    push_str("scsi-options");
    fword("property");

    PUSH(0x24);
    fword("encode-int");
    PUSH(0);
    fword("encode-int");
    fword("encode+");
    push_str("intr");
    fword("property");
}

static void
ob_esp_decodeunit(__attribute__((unused)) esp_private_t **esp)
{
    fword("decode-unit-scsi");
}


static void
ob_esp_encodeunit(__attribute__((unused)) esp_private_t **esp)
{
    fword("encode-unit-scsi");
}

NODE_METHODS(ob_esp) = {
    { NULL,             ob_esp_initialize },
    { "decode-unit",    ob_esp_decodeunit },
    { "encode-unit",    ob_esp_encodeunit },
};

static void
add_alias(const char *device, const char *alias)
{
    DPRINTF("add_alias dev \"%s\" = alias \"%s\"\n", device, alias);
    push_str("/aliases");
    fword("find-device");
    push_str(device);
    fword("encode-string");
    push_str(alias);
    fword("property");
}

int
ob_esp_init(unsigned int slot, uint64_t base, unsigned long espoffset,
            unsigned long dmaoffset)
{
    int id, diskcount = 0, cdcount = 0, *counter_ptr;
    char nodebuff[256], aliasbuff[256];
    esp_private_t *esp;
    unsigned int i;

    DPRINTF("Initializing SCSI...");

    esp = malloc(sizeof(esp_private_t));
    if (!esp) {
        DPRINTF("Can't allocate ESP private structure\n");
        return -1;
    }

    global_esp = esp;

    if (espdma_init(slot, base, dmaoffset, &esp->espdma) != 0) {
        return -1;
    }
    /* Get the IO region */
    esp->ll = (void *)ofmem_map_io(base + (uint64_t)espoffset,
                             sizeof(struct esp_regs));
    if (esp->ll == NULL) {
        DPRINTF("Can't map ESP registers\n");
        return -1;
    }

    esp->buffer = (void *)dvma_alloc(BUFSIZE, &esp->buffer_dvma);
    if (!esp->buffer || !esp->buffer_dvma) {
        DPRINTF("Can't get a DVMA buffer\n");
        return -1;
    }

    // Chip reset
    esp->ll->regs[ESP_CMD] = ESP_CMD_RC;

    DPRINTF("ESP at 0x%lx, buffer va 0x%lx dva 0x%lx\n", (unsigned long)esp,
            (unsigned long)esp->buffer, (unsigned long)esp->buffer_dvma);
    DPRINTF("done\n");
    DPRINTF("Initializing SCSI devices...");

    for (id = 0; id < 8; id++) {
        esp->sd[id].id = id;
        if (!inquiry(esp, &esp->sd[id])) {
            DPRINTF("Unit %d not present\n", id);
            continue;
        }
        /* Clear Unit Attention condition from reset */
        for (i = 0; i < 5; i++) {
            if (test_unit_ready(esp, &esp->sd[id])) {
                break;
            }
        }
        if (i == 5) {
            DPRINTF("Unit %d present but won't become ready\n", id);
            continue;
        }
        DPRINTF("Unit %d present\n", id);
        read_capacity(esp, &esp->sd[id]);

#ifdef CONFIG_DEBUG_ESP
        dump_drive(&esp->sd[id]);
#endif
    }

    REGISTER_NAMED_NODE(ob_esp, "/iommu/sbus/espdma/esp");
    device_end();
    /* set reg */
    push_str("/iommu/sbus/espdma/esp");
    fword("find-device");
    PUSH(slot);
    fword("encode-int");
    PUSH(espoffset);
    fword("encode-int");
    fword("encode+");
    PUSH(0x00000010);
    fword("encode-int");
    fword("encode+");
    push_str("reg");
    fword("property");

    PUSH(0x02625a00);
    fword("encode-int");
    push_str("clock-frequency");
    fword("property");

    for (id = 0; id < 8; id++) {
        if (!esp->sd[id].present)
            continue;
        push_str("/iommu/sbus/espdma/esp");
        fword("find-device");
        fword("new-device");
        push_str("sd");
        fword("device-name");
        push_str("block");
        fword("device-type");
        fword("is-deblocker");
        PUSH(id);
        fword("encode-int");
        PUSH(0);
        fword("encode-int");
        fword("encode+");
        push_str("reg");
        fword("property");
        fword("finish-device");
        snprintf(nodebuff, sizeof(nodebuff), "/iommu/sbus/espdma/esp/sd@%d,0",
                 id);
        REGISTER_NODE_METHODS(ob_sd, nodebuff);
        if (esp->sd[id].media == TYPE_ROM) {
            counter_ptr = &cdcount;
        } else {
            counter_ptr = &diskcount;
        }
        if (*counter_ptr == 0) {
            add_alias(nodebuff, esp->sd[id].media_str[0]);
            add_alias(nodebuff, esp->sd[id].media_str[1]);
        }
        snprintf(aliasbuff, sizeof(aliasbuff), "%s%d",
                 esp->sd[id].media_str[0], *counter_ptr);
        add_alias(nodebuff, aliasbuff);
        snprintf(aliasbuff, sizeof(aliasbuff), "%s%d",
                 esp->sd[id].media_str[1], *counter_ptr);
        add_alias(nodebuff, aliasbuff);
        snprintf(aliasbuff, sizeof(aliasbuff), "sd(0,%d,0)", id);
        add_alias(nodebuff, aliasbuff);
        snprintf(aliasbuff, sizeof(aliasbuff), "sd(0,%d,0)@0,0", id);
        add_alias(nodebuff, aliasbuff);
        (*counter_ptr)++;
    }
    DPRINTF("done\n");

    return 0;
}
