// Support for manipulating bios tables (pir, mptable, acpi, smbios).
//
// Copyright (C) 2008,2009  Kevin O'Connor <kevin@koconnor.net>
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "byteorder.h" // le32_to_cpu
#include "config.h" // CONFIG_*
#include "malloc.h" // malloc_fseg
#include "output.h" // dprintf
#include "hw/pci.h" // pci_config_writeb
#include "std/acpi.h" // struct rsdp_descriptor
#include "std/mptable.h" // MPTABLE_SIGNATURE
#include "std/pirtable.h" // struct pir_header
#include "std/smbios.h" // struct smbios_entry_point
#include "romfile.h"
#include "string.h" // memcpy
#include "util.h" // copy_table
#include "x86.h" // outb

struct pir_header *PirAddr VARFSEG;

void
copy_pir(void *pos)
{
    struct pir_header *p = pos;
    if (p->signature != PIR_SIGNATURE)
        return;
    if (PirAddr)
        return;
    if (p->size < sizeof(*p))
        return;
    if (checksum(pos, p->size) != 0)
        return;
    void *newpos = malloc_fseg(p->size);
    if (!newpos) {
        warn_noalloc();
        return;
    }
    dprintf(1, "Copying PIR from %p to %p\n", pos, newpos);
    memcpy(newpos, pos, p->size);
    PirAddr = newpos;
}

void
copy_mptable(void *pos)
{
    struct mptable_floating_s *p = pos;
    if (p->signature != MPTABLE_SIGNATURE)
        return;
    if (!p->physaddr)
        return;
    if (checksum(pos, sizeof(*p)) != 0)
        return;
    u32 length = p->length * 16;
    u16 mpclength = ((struct mptable_config_s *)p->physaddr)->length;
    // Allocate final memory location.  (In theory the config
    // structure can go in high memory, but Linux kernels before
    // v2.6.30 crash with that.)
    struct mptable_floating_s *newpos = malloc_fseg(length + mpclength);
    if (!newpos) {
        warn_noalloc();
        return;
    }
    dprintf(1, "Copying MPTABLE from %p/%x to %p\n", pos, p->physaddr, newpos);
    memcpy(newpos, pos, length);
    newpos->physaddr = (u32)newpos + length;
    newpos->checksum -= checksum(newpos, sizeof(*newpos));
    memcpy((void*)newpos + length, (void*)p->physaddr, mpclength);
}


/****************************************************************
 * ACPI
 ****************************************************************/

static int
get_acpi_rsdp_length(void *pos, unsigned size)
{
    struct rsdp_descriptor *p = pos;
    if (p->signature != RSDP_SIGNATURE)
        return -1;
    u32 length = 20;
    if (length > size)
        return -1;
    if (checksum(pos, length) != 0)
        return -1;
    if (p->revision > 1) {
        length = p->length;
        if (length > size)
            return -1;
        if (checksum(pos, length) != 0)
            return -1;
    }
    return length;
}

struct rsdp_descriptor *RsdpAddr;

void
copy_acpi_rsdp(void *pos)
{
    if (RsdpAddr)
        return;
    int length = get_acpi_rsdp_length(pos, -1);
    if (length < 0)
        return;
    void *newpos = malloc_fseg(length);
    if (!newpos) {
        warn_noalloc();
        return;
    }
    dprintf(1, "Copying ACPI RSDP from %p to %p\n", pos, newpos);
    memcpy(newpos, pos, length);
    RsdpAddr = newpos;
}

void *find_acpi_rsdp(void)
{
    extern u8 zonefseg_start[], zonefseg_end[];
    unsigned long start = (unsigned long)zonefseg_start;
    unsigned long end = (unsigned long)zonefseg_end;
    unsigned long pos;

    for (pos = ALIGN(start, 0x10); pos <= ALIGN_DOWN(end, 0x10); pos += 0x10)
        if (get_acpi_rsdp_length((void *)pos, end - pos) >= 0)
            return (void *)pos;

    return NULL;
}

static struct fadt_descriptor_rev1 *
find_fadt(void)
{
    dprintf(4, "rsdp=%p\n", RsdpAddr);
    if (!RsdpAddr || RsdpAddr->signature != RSDP_SIGNATURE)
        return NULL;
    struct rsdt_descriptor_rev1 *rsdt = (void*)RsdpAddr->rsdt_physical_address;
    dprintf(4, "rsdt=%p\n", rsdt);
    if (!rsdt || rsdt->signature != RSDT_SIGNATURE)
        return NULL;
    void *end = (void*)rsdt + rsdt->length;
    int i;
    for (i=0; (void*)&rsdt->table_offset_entry[i] < end; i++) {
        struct fadt_descriptor_rev1 *fadt = (void*)rsdt->table_offset_entry[i];
        if (!fadt || fadt->signature != FACP_SIGNATURE)
            continue;
        dprintf(4, "fadt=%p\n", fadt);
        return fadt;
    }
    dprintf(4, "no fadt found\n");
    return NULL;
}

u32
find_resume_vector(void)
{
    struct fadt_descriptor_rev1 *fadt = find_fadt();
    if (!fadt)
        return 0;
    struct facs_descriptor_rev1 *facs = (void*)fadt->firmware_ctrl;
    dprintf(4, "facs=%p\n", facs);
    if (! facs || facs->signature != FACS_SIGNATURE)
        return 0;
    // Found it.
    dprintf(4, "resume addr=%d\n", facs->firmware_waking_vector);
    return facs->firmware_waking_vector;
}

static struct acpi_20_generic_address acpi_reset_reg;
static u8 acpi_reset_val;
u32 acpi_pm1a_cnt VARFSEG;
u16 acpi_pm_base = 0xb000;

#define acpi_ga_to_bdf(addr) pci_to_bdf(0, (addr >> 32) & 0xffff, (addr >> 16) & 0xffff)

void
acpi_reboot(void)
{
    // Check it passed the sanity checks in acpi_set_reset_reg() and was set
    if (acpi_reset_reg.register_bit_width != 8)
        return;

    u64 addr = le64_to_cpu(acpi_reset_reg.address);

    dprintf(1, "ACPI hard reset %d:%llx (%x)\n",
            acpi_reset_reg.address_space_id, addr, acpi_reset_val);

    switch (acpi_reset_reg.address_space_id) {
    case 0: // System Memory
        writeb((void *)(u32)addr, acpi_reset_val);
        break;
    case 1: // System I/O
        outb(acpi_reset_val, addr);
        break;
    case 2: // PCI config space
        pci_config_writeb(acpi_ga_to_bdf(addr), addr & 0xffff, acpi_reset_val);
        break;
    }
}

static void
acpi_set_reset_reg(struct acpi_20_generic_address *reg, u8 val)
{
    if (!reg || reg->address_space_id > 2 ||
        reg->register_bit_width != 8 || reg->register_bit_offset)
        return;

    acpi_reset_reg = *reg;
    acpi_reset_val = val;
}

void
find_acpi_features(void)
{
    struct fadt_descriptor_rev1 *fadt = find_fadt();
    if (!fadt)
        return;
    u32 pm_tmr = le32_to_cpu(fadt->pm_tmr_blk);
    u32 pm1a_cnt = le32_to_cpu(fadt->pm1a_cnt_blk);
    dprintf(4, "pm_tmr_blk=%x\n", pm_tmr);
    if (pm_tmr)
        pmtimer_setup(pm_tmr);
    if (pm1a_cnt)
        acpi_pm1a_cnt = pm1a_cnt;

    // Theoretically we should check the 'reset_reg_sup' flag, but Windows
    // doesn't and thus nobody seems to *set* it. If the table is large enough
    // to include it, let the sanity checks in acpi_set_reset_reg() suffice.
    if (fadt->length >= 129) {
        void *p = fadt;
        acpi_set_reset_reg(p + 116, *(u8 *)(p + 128));
    }
}


/****************************************************************
 * SMBIOS
 ****************************************************************/

// Iterator for each sub-table in the smbios blob.
void *
smbios_next(struct smbios_entry_point *smbios, void *prev)
{
    if (!smbios)
        return NULL;
    void *start = (void*)smbios->structure_table_address;
    void *end = start + smbios->structure_table_length;

    if (!prev) {
        prev = start;
    } else {
        struct smbios_structure_header *hdr = prev;
        if (prev + sizeof(*hdr) > end)
            return NULL;
        prev += hdr->length + 2;
        while (prev < end && (*(u8*)(prev-1) != '\0' || *(u8*)(prev-2) != '\0'))
            prev++;
    }
    struct smbios_structure_header *hdr = prev;
    if (prev >= end || prev + sizeof(*hdr) >= end || prev + hdr->length >= end)
        return NULL;
    return prev;
}

struct smbios_entry_point *SMBiosAddr;

void
copy_smbios(void *pos)
{
    if (SMBiosAddr)
        return;
    struct smbios_entry_point *p = pos;
    if (memcmp(p->anchor_string, "_SM_", 4))
        return;
    if (checksum(pos, 0x10) != 0)
        return;
    if (memcmp(p->intermediate_anchor_string, "_DMI_", 5))
        return;
    if (checksum(pos+0x10, p->length-0x10) != 0)
        return;
    struct smbios_entry_point *newpos = malloc_fseg(p->length);
    if (!newpos) {
        warn_noalloc();
        return;
    }
    dprintf(1, "Copying SMBIOS entry point from %p to %p\n", pos, newpos);
    memcpy(newpos, pos, p->length);
    SMBiosAddr = newpos;
}

void
display_uuid(void)
{
    struct smbios_type_1 *tbl = smbios_next(SMBiosAddr, NULL);
    int minlen = offsetof(struct smbios_type_1, uuid) + sizeof(tbl->uuid);
    for (; tbl; tbl = smbios_next(SMBiosAddr, tbl))
        if (tbl->header.type == 1 && tbl->header.length >= minlen) {
            u8 *uuid = tbl->uuid;
            u8 empty_uuid[sizeof(tbl->uuid)] = { 0 };
            if (memcmp(uuid, empty_uuid, sizeof(empty_uuid)) == 0)
                return;

            printf("Machine UUID"
                   " %02x%02x%02x%02x"
                   "-%02x%02x"
                   "-%02x%02x"
                   "-%02x%02x"
                   "-%02x%02x%02x%02x%02x%02x\n"
                   , uuid[ 0], uuid[ 1], uuid[ 2], uuid[ 3]
                   , uuid[ 4], uuid[ 5]
                   , uuid[ 6], uuid[ 7]
                   , uuid[ 8], uuid[ 9]
                   , uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]);
            return;
        }
}

#define set_str_field_or_skip(type, field, value)                       \
    do {                                                                \
        int size = (value != NULL) ? strlen(value) + 1 : 0;             \
        if (size > 1) {                                                 \
            memcpy(end, value, size);                                   \
            end += size;                                                \
            p->field = ++str_index;                                     \
        } else {                                                        \
            p->field = 0;                                               \
        }                                                               \
    } while (0)

static void *
smbios_new_type_0(void *start,
                  const char *vendor, const char *version, const char *date)
{
    struct smbios_type_0 *p = (struct smbios_type_0 *)start;
    char *end = (char *)start + sizeof(struct smbios_type_0);
    int str_index = 0;

    p->header.type = 0;
    p->header.length = sizeof(struct smbios_type_0);
    p->header.handle = 0;

    set_str_field_or_skip(0, vendor_str, vendor);
    set_str_field_or_skip(0, bios_version_str, version);
    p->bios_starting_address_segment = 0xe800;
    set_str_field_or_skip(0, bios_release_date_str, date);

    p->bios_rom_size = 0; /* FIXME */

    /* BIOS characteristics not supported */
    memset(p->bios_characteristics, 0, 8);
    p->bios_characteristics[0] = 0x08;

    /* Enable targeted content distribution (needed for SVVP) */
    p->bios_characteristics_extension_bytes[0] = 0;
    p->bios_characteristics_extension_bytes[1] = 4;

    p->system_bios_major_release = 0;
    p->system_bios_minor_release = 0;
    p->embedded_controller_major_release = 0xFF;
    p->embedded_controller_minor_release = 0xFF;

    *end = 0;
    end++;
    if (!str_index) {
        *end = 0;
        end++;
    }

    return end;
}

#define BIOS_NAME "SeaBIOS"
#define BIOS_DATE "04/01/2014"

static int
smbios_romfile_setup(void)
{
    struct romfile_s *f_anchor = romfile_find("etc/smbios/smbios-anchor");
    struct romfile_s *f_tables = romfile_find("etc/smbios/smbios-tables");
    struct smbios_entry_point ep;
    struct smbios_type_0 *t0;
    u16 qtables_len, need_t0 = 1;
    u8 *qtables, *tables;

    if (!f_anchor || !f_tables || f_anchor->size != sizeof(ep))
        return 0;

    f_anchor->copy(f_anchor, &ep, f_anchor->size);

    if (f_tables->size != ep.structure_table_length)
        return 0;

    qtables = malloc_tmphigh(f_tables->size);
    if (!qtables) {
        warn_noalloc();
        return 0;
    }
    f_tables->copy(f_tables, qtables, f_tables->size);
    ep.structure_table_address = (u32)qtables; /* for smbios_next(), below */

    /* did we get a type 0 structure ? */
    for (t0 = smbios_next(&ep, NULL); t0; t0 = smbios_next(&ep, t0))
        if (t0->header.type == 0) {
            need_t0 = 0;
            break;
        }

    qtables_len = ep.structure_table_length;
    if (need_t0) {
        /* common case: add our own type 0, with 3 strings and 4 '\0's */
        u16 t0_len = sizeof(struct smbios_type_0) + strlen(BIOS_NAME) +
                     strlen(VERSION) + strlen(BIOS_DATE) + 4;
        ep.structure_table_length += t0_len;
        if (t0_len > ep.max_structure_size)
            ep.max_structure_size = t0_len;
        ep.number_of_structures++;
    }

    /* allocate final blob and record its address in the entry point */
    if (ep.structure_table_length > BUILD_MAX_SMBIOS_FSEG)
        tables = malloc_high(ep.structure_table_length);
    else
        tables = malloc_fseg(ep.structure_table_length);
    if (!tables) {
        warn_noalloc();
        free(qtables);
        return 0;
    }
    ep.structure_table_address = (u32)tables;

    /* populate final blob */
    if (need_t0)
        tables = smbios_new_type_0(tables, BIOS_NAME, VERSION, BIOS_DATE);
    memcpy(tables, qtables, qtables_len);
    free(qtables);

    /* finalize entry point */
    ep.checksum -= checksum(&ep, 0x10);
    ep.intermediate_checksum -= checksum((void *)&ep + 0x10, ep.length - 0x10);

    copy_smbios(&ep);
    return 1;
}

void
smbios_setup(void)
{
    if (smbios_romfile_setup())
      return;
    smbios_legacy_setup();
}

void
copy_table(void *pos)
{
    copy_pir(pos);
    copy_mptable(pos);
    copy_acpi_rsdp(pos);
    copy_smbios(pos);
}
