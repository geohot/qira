// Code for emulating a drive via high-memory accesses.
//
// Copyright (C) 2009  Kevin O'Connor <kevin@koconnor.net>
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "biosvar.h" // GET_GLOBALFLAT
#include "block.h" // struct drive_s
#include "bregs.h" // struct bregs
#include "malloc.h" // malloc_fseg
#include "memmap.h" // add_e820
#include "output.h" // dprintf
#include "romfile.h" // romfile_findprefix
#include "stacks.h" // call16_int
#include "std/disk.h" // DISK_RET_SUCCESS
#include "string.h" // memset
#include "util.h" // process_ramdisk_op

void
ramdisk_setup(void)
{
    if (!CONFIG_FLASH_FLOPPY)
        return;

    // Find image.
    struct romfile_s *file = romfile_findprefix("floppyimg/", NULL);
    if (!file)
        return;
    const char *filename = file->name;
    u32 size = file->size;
    dprintf(3, "Found floppy file %s of size %d\n", filename, size);
    int ftype = find_floppy_type(size);
    if (ftype < 0) {
        dprintf(3, "No floppy type found for ramdisk size\n");
        return;
    }

    // Allocate ram for image.
    void *pos = memalign_tmphigh(PAGE_SIZE, size);
    if (!pos) {
        warn_noalloc();
        return;
    }
    add_e820((u32)pos, size, E820_RESERVED);

    // Copy image into ram.
    int ret = file->copy(file, pos, size);
    if (ret < 0)
        return;

    // Setup driver.
    struct drive_s *drive = init_floppy((u32)pos, ftype);
    if (!drive)
        return;
    drive->type = DTYPE_RAMDISK;
    dprintf(1, "Mapping CBFS floppy %s to addr %p\n", filename, pos);
    char *desc = znprintf(MAXDESCSIZE, "Ramdisk [%s]", &filename[10]);
    boot_add_floppy(drive, desc, bootprio_find_named_rom(filename, 0));
}

static int
ramdisk_copy(struct disk_op_s *op, int iswrite)
{
    u32 offset = GET_GLOBALFLAT(op->drive_gf->cntl_id);
    offset += (u32)op->lba * DISK_SECTOR_SIZE;
    u64 opd = GDT_DATA | GDT_LIMIT(0xfffff) | GDT_BASE((u32)op->buf_fl);
    u64 ramd = GDT_DATA | GDT_LIMIT(0xfffff) | GDT_BASE(offset);

    u64 gdt[6];
    if (iswrite) {
        gdt[2] = opd;
        gdt[3] = ramd;
    } else {
        gdt[2] = ramd;
        gdt[3] = opd;
    }

    // Call int 1587 to copy data.
    struct bregs br;
    memset(&br, 0, sizeof(br));
    br.flags = F_CF|F_IF;
    br.ah = 0x87;
    br.es = GET_SEG(SS);
    br.si = (u32)gdt;
    br.cx = op->count * DISK_SECTOR_SIZE / 2;
    call16_int(0x15, &br);

    if (br.flags & F_CF)
        return DISK_RET_EBADTRACK;
    return DISK_RET_SUCCESS;
}

int
process_ramdisk_op(struct disk_op_s *op)
{
    if (!CONFIG_FLASH_FLOPPY)
        return 0;

    switch (op->command) {
    case CMD_READ:
        return ramdisk_copy(op, 0);
    case CMD_WRITE:
        return ramdisk_copy(op, 1);
    case CMD_VERIFY:
    case CMD_FORMAT:
    case CMD_RESET:
        return DISK_RET_SUCCESS;
    default:
        return DISK_RET_EPARAM;
    }
}
