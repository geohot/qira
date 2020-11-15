// Coreboot interface support.
//
// Copyright (C) 2008,2009  Kevin O'Connor <kevin@koconnor.net>
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "block.h" // MAXDESCSIZE
#include "byteorder.h" // be32_to_cpu
#include "config.h" // CONFIG_*
#include "hw/pci.h" // pci_probe_devices
#include "lzmadecode.h" // LzmaDecode
#include "malloc.h" // free
#include "memmap.h" // add_e820
#include "output.h" // dprintf
#include "paravirt.h" // PlatformRunningOn
#include "romfile.h" // romfile_findprefix
#include "stacks.h" // yield
#include "string.h" // memset
#include "util.h" // coreboot_preinit


/****************************************************************
 * Memory map
 ****************************************************************/

struct cb_header {
    u32 signature;
    u32 header_bytes;
    u32 header_checksum;
    u32 table_bytes;
    u32 table_checksum;
    u32 table_entries;
};

#define CB_SIGNATURE 0x4f49424C // "LBIO"

struct cb_memory_range {
    u64 start;
    u64 size;
    u32 type;
};

#define CB_MEM_TABLE    16

struct cb_memory {
    u32 tag;
    u32 size;
    struct cb_memory_range map[0];
};

#define CB_TAG_MEMORY 0x01

#define MEM_RANGE_COUNT(_rec) \
        (((_rec)->size - sizeof(*(_rec))) / sizeof((_rec)->map[0]))

struct cb_mainboard {
    u32 tag;
    u32 size;
    u8  vendor_idx;
    u8  part_idx;
    char  strings[0];
};

#define CB_TAG_MAINBOARD 0x0003

struct cb_forward {
    u32 tag;
    u32 size;
    u64 forward;
};

#define CB_TAG_FORWARD 0x11

struct cb_cbmem_ref {
    u32 tag;
    u32 size;
    u64 cbmem_addr;
};

#define CB_TAG_CBMEM_CONSOLE 0x17

struct cbmem_console {
    u32 buffer_size;
    u32 buffer_cursor;
    u8  buffer_body[0];
} PACKED;
static struct cbmem_console *cbcon = NULL;

static u16
ipchksum(char *buf, int count)
{
    u16 *p = (u16*)buf;
    u32 sum = 0;
    while (count > 1) {
        sum += GET_FARVAR(0, *p);
        p++;
        count -= 2;
    }
    if (count)
        sum += GET_FARVAR(0, *(u8*)p);
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}

// Try to locate the coreboot header in a given address range.
static struct cb_header *
find_cb_header(u32 addr, int len)
{
    u32 end = addr + len;
    for (; addr < end; addr += 16) {
        struct cb_header *cbh = (void*)addr;
        if (GET_FARVAR(0, cbh->signature) != CB_SIGNATURE)
            continue;
        u32 tsize = GET_FARVAR(0, cbh->table_bytes);
        if (! tsize)
            continue;
        if (ipchksum((void*)addr, sizeof(*cbh)) != 0)
            continue;
        if (ipchksum((void*)addr + sizeof(*cbh), tsize)
            != GET_FARVAR(0, cbh->table_checksum))
            continue;
        return cbh;
    }
    return NULL;
}

// Try to find the coreboot memory table in the given coreboot table.
void *
find_cb_subtable(struct cb_header *cbh, u32 tag)
{
    char *tbl = (char *)cbh + sizeof(*cbh);
    u32 count = GET_FARVAR(0, cbh->table_entries);
    int i;
    for (i=0; i<count; i++) {
        struct cb_memory *cbm = (void*)tbl;
        tbl += GET_FARVAR(0, cbm->size);
        if (GET_FARVAR(0, cbm->tag) == tag)
            return cbm;
    }
    return NULL;
}

struct cb_header *
find_cb_table(void)
{
    struct cb_header *cbh = find_cb_header(0, 0x1000);
    if (!cbh)
        return NULL;
    struct cb_forward *cbf = find_cb_subtable(cbh, CB_TAG_FORWARD);
    if (cbf) {
        dprintf(3, "Found coreboot table forwarder.\n");
        cbh = find_cb_header(GET_FARVAR(0, cbf->forward), 0x100);
        if (!cbh)
            return NULL;
    }
    return cbh;
}

static struct cb_memory *CBMemTable;
const char *CBvendor = "", *CBpart = "";

// Populate max ram and e820 map info by scanning for a coreboot table.
void
coreboot_preinit(void)
{
    if (!CONFIG_COREBOOT)
        return;

    dprintf(3, "Attempting to find coreboot table\n");

    // Find coreboot table.
    struct cb_header *cbh = find_cb_table();
    if (!cbh)
        goto fail;
    dprintf(3, "Now attempting to find coreboot memory map\n");
    struct cb_memory *cbm = CBMemTable = find_cb_subtable(cbh, CB_TAG_MEMORY);
    if (!cbm)
        goto fail;

    int i, count = MEM_RANGE_COUNT(cbm);
    for (i=0; i<count; i++) {
        struct cb_memory_range *m = &cbm->map[i];
        u32 type = m->type;
        if (type == CB_MEM_TABLE)
            type = E820_RESERVED;
        add_e820(m->start, m->size, type);
    }

    // Ughh - coreboot likes to set a map at 0x0000-0x1000, but this
    // confuses grub.  So, override it.
    add_e820(0, 16*1024, E820_RAM);

    struct cb_cbmem_ref *cbref = find_cb_subtable(cbh, CB_TAG_CBMEM_CONSOLE);
    if (cbref) {
        cbcon = (void*)(u32)cbref->cbmem_addr;
        debug_banner();
        dprintf(1, "Found coreboot cbmem console @ %llx\n", cbref->cbmem_addr);
    }

    struct cb_mainboard *cbmb = find_cb_subtable(cbh, CB_TAG_MAINBOARD);
    if (cbmb) {
        CBvendor = &cbmb->strings[cbmb->vendor_idx];
        CBpart = &cbmb->strings[cbmb->part_idx];
        dprintf(1, "Found mainboard %s %s\n", CBvendor, CBpart);
    }

    return;

fail:
    // No table found..  Use 16Megs as a dummy value.
    dprintf(1, "Unable to find coreboot table!\n");
    add_e820(0, 16*1024*1024, E820_RAM);
    return;
}

void coreboot_debug_putc(char c)
{
    if (!CONFIG_DEBUG_COREBOOT)
        return;
    if (!cbcon)
        return;
    u32 cursor = cbcon->buffer_cursor++;
    if (cursor < cbcon->buffer_size)
        cbcon->buffer_body[cursor] = c;
}

/****************************************************************
 * BIOS table copying
 ****************************************************************/

// Attempt to find (and relocate) any standard bios tables found in a
// given address range.
static void
scan_tables(u32 start, u32 size)
{
    void *p = (void*)ALIGN(start, 16);
    void *end = (void*)start + size;
    for (; p<end; p += 16)
        copy_table(p);
}

void
coreboot_platform_setup(void)
{
    if (!CONFIG_COREBOOT)
        return;
    pci_probe_devices();

    struct cb_memory *cbm = CBMemTable;
    if (!cbm)
        return;

    dprintf(3, "Relocating coreboot bios tables\n");

    // Scan CB_MEM_TABLE areas for bios tables.
    int i, count = MEM_RANGE_COUNT(cbm);
    for (i=0; i<count; i++) {
        struct cb_memory_range *m = &cbm->map[i];
        if (m->type == CB_MEM_TABLE)
            scan_tables(m->start, m->size);
    }

    find_acpi_features();
}


/****************************************************************
 * ulzma
 ****************************************************************/

// Uncompress data in flash to an area of memory.
static int
ulzma(u8 *dst, u32 maxlen, const u8 *src, u32 srclen)
{
    dprintf(3, "Uncompressing data %d@%p to %d@%p\n", srclen, src, maxlen, dst);
    CLzmaDecoderState state;
    int ret = LzmaDecodeProperties(&state.Properties, src, LZMA_PROPERTIES_SIZE);
    if (ret != LZMA_RESULT_OK) {
        dprintf(1, "LzmaDecodeProperties error - %d\n", ret);
        return -1;
    }
    u8 scratch[15980];
    int need = (LzmaGetNumProbs(&state.Properties) * sizeof(CProb));
    if (need > sizeof(scratch)) {
        dprintf(1, "LzmaDecode need %d have %d\n", need, (unsigned int)sizeof(scratch));
        return -1;
    }
    state.Probs = (CProb *)scratch;

    u32 dstlen = *(u32*)(src + LZMA_PROPERTIES_SIZE);
    if (dstlen > maxlen) {
        dprintf(1, "LzmaDecode too large (max %d need %d)\n", maxlen, dstlen);
        return -1;
    }
    u32 inProcessed, outProcessed;
    ret = LzmaDecode(&state, src + LZMA_PROPERTIES_SIZE + 8, srclen
                     , &inProcessed, dst, dstlen, &outProcessed);
    if (ret) {
        dprintf(1, "LzmaDecode returned %d\n", ret);
        return -1;
    }
    return dstlen;
}


/****************************************************************
 * Coreboot flash format
 ****************************************************************/

#define CBFS_HEADER_MAGIC 0x4F524243
#define CBFS_VERSION1 0x31313131

struct cbfs_header {
    u32 magic;
    u32 version;
    u32 romsize;
    u32 bootblocksize;
    u32 align;
    u32 offset;
    u32 pad[2];
} PACKED;

#define CBFS_FILE_MAGIC 0x455649484352414cLL // LARCHIVE

struct cbfs_file {
    u64 magic;
    u32 len;
    u32 type;
    u32 checksum;
    u32 offset;
    char filename[0];
} PACKED;

struct cbfs_romfile_s {
    struct romfile_s file;
    struct cbfs_file *fhdr;
    void *data;
    u32 rawsize, flags;
};

// Copy a file to memory (uncompressing if necessary)
static int
cbfs_copyfile(struct romfile_s *file, void *dst, u32 maxlen)
{
    if (!CONFIG_COREBOOT_FLASH)
        return -1;

    struct cbfs_romfile_s *cfile;
    cfile = container_of(file, struct cbfs_romfile_s, file);
    u32 size = cfile->rawsize;
    void *src = cfile->data;
    if (cfile->flags) {
        // Compressed - copy to temp ram and uncompress it.
        void *temp = malloc_tmphigh(size);
        if (!temp) {
            warn_noalloc();
            return -1;
        }
        iomemcpy(temp, src, size);
        int ret = ulzma(dst, maxlen, temp, size);
        yield();
        free(temp);
        return ret;
    }

    // Not compressed.
    dprintf(3, "Copying data %d@%p to %d@%p\n", size, src, maxlen, dst);
    if (size > maxlen) {
        warn_noalloc();
        return -1;
    }
    iomemcpy(dst, src, size);
    return size;
}

// Process CBFS links file.  The links file is a newline separated
// file where each line has a "link name" and a "destination name"
// separated by a space character.
static void
process_links_file(void)
{
    char *links = romfile_loadfile("links", NULL), *next = links;
    while (next) {
        // Parse out linkname and destname
        char *linkname = next;
        next = strchr(linkname, '\n');
        if (next)
            *next++ = '\0';
        char *comment = strchr(linkname, '#');
        if (comment)
            *comment = '\0';
        linkname = nullTrailingSpace(linkname);
        char *destname = strchr(linkname, ' ');
        if (!destname)
            continue;
        *destname++ = '\0';
        destname = nullTrailingSpace(destname);
        // Lookup destname and create new romfile entry for linkname
        struct romfile_s *ufile = romfile_find(destname);
        if (!ufile)
            continue;
        struct cbfs_romfile_s *cufile
            = container_of(ufile, struct cbfs_romfile_s, file);
        struct cbfs_romfile_s *cfile = malloc_tmp(sizeof(*cfile));
        if (!cfile) {
            warn_noalloc();
            break;
        }
        memcpy(cfile, cufile, sizeof(*cfile));
        strtcpy(cfile->file.name, linkname, sizeof(cfile->file.name));
        romfile_add(&cfile->file);
    }
    free(links);
}

void
coreboot_cbfs_init(void)
{
    if (!CONFIG_COREBOOT_FLASH)
        return;

    struct cbfs_header *hdr = *(void **)(CONFIG_CBFS_LOCATION - 4);
    if (hdr->magic != cpu_to_be32(CBFS_HEADER_MAGIC)) {
        dprintf(1, "Unable to find CBFS (ptr=%p; got %x not %x)\n"
                , hdr, hdr->magic, cpu_to_be32(CBFS_HEADER_MAGIC));
        return;
    }
    dprintf(1, "Found CBFS header at %p\n", hdr);

    u32 romsize = be32_to_cpu(hdr->romsize);
    u32 romstart = CONFIG_CBFS_LOCATION - romsize;
    struct cbfs_file *fhdr = (void*)romstart + be32_to_cpu(hdr->offset);
    for (;;) {
        if ((u32)fhdr - romstart > romsize)
            break;
        u64 magic = fhdr->magic;
        if (magic != CBFS_FILE_MAGIC)
            break;
        struct cbfs_romfile_s *cfile = malloc_tmp(sizeof(*cfile));
        if (!cfile) {
            warn_noalloc();
            break;
        }
        memset(cfile, 0, sizeof(*cfile));
        strtcpy(cfile->file.name, fhdr->filename, sizeof(cfile->file.name));
        cfile->file.size = cfile->rawsize = be32_to_cpu(fhdr->len);
        cfile->fhdr = fhdr;
        cfile->file.copy = cbfs_copyfile;
        cfile->data = (void*)fhdr + be32_to_cpu(fhdr->offset);
        int len = strlen(cfile->file.name);
        if (len > 5 && strcmp(&cfile->file.name[len-5], ".lzma") == 0) {
            // Using compression.
            cfile->flags = 1;
            cfile->file.name[len-5] = '\0';
            cfile->file.size = *(u32*)(cfile->data + LZMA_PROPERTIES_SIZE);
        }
        romfile_add(&cfile->file);

        fhdr = (void*)ALIGN((u32)cfile->data + cfile->rawsize
                            , be32_to_cpu(hdr->align));
    }

    process_links_file();
}

struct cbfs_payload_segment {
    u32 type;
    u32 compression;
    u32 offset;
    u64 load_addr;
    u32 len;
    u32 mem_len;
} PACKED;

#define PAYLOAD_SEGMENT_BSS    0x20535342
#define PAYLOAD_SEGMENT_ENTRY  0x52544E45

#define CBFS_COMPRESS_NONE  0
#define CBFS_COMPRESS_LZMA  1

struct cbfs_payload {
    struct cbfs_payload_segment segments[1];
};

void
cbfs_run_payload(struct cbfs_file *fhdr)
{
    if (!CONFIG_COREBOOT_FLASH || !fhdr)
        return;
    dprintf(1, "Run %s\n", fhdr->filename);
    struct cbfs_payload *pay = (void*)fhdr + be32_to_cpu(fhdr->offset);
    struct cbfs_payload_segment *seg = pay->segments;
    for (;;) {
        void *src = (void*)pay + be32_to_cpu(seg->offset);
        void *dest = (void*)(u32)be64_to_cpu(seg->load_addr);
        u32 src_len = be32_to_cpu(seg->len);
        u32 dest_len = be32_to_cpu(seg->mem_len);
        switch (seg->type) {
        case PAYLOAD_SEGMENT_BSS:
            dprintf(3, "BSS segment %d@%p\n", dest_len, dest);
            memset(dest, 0, dest_len);
            break;
        case PAYLOAD_SEGMENT_ENTRY: {
            dprintf(1, "Calling addr %p\n", dest);
            void (*func)() = dest;
            func();
            return;
        }
        default:
            dprintf(3, "Segment %x %d@%p -> %d@%p\n"
                    , seg->type, src_len, src, dest_len, dest);
            if (seg->compression == cpu_to_be32(CBFS_COMPRESS_NONE)) {
                if (src_len > dest_len)
                    src_len = dest_len;
                memcpy(dest, src, src_len);
            } else if (CONFIG_LZMA
                       && seg->compression == cpu_to_be32(CBFS_COMPRESS_LZMA)) {
                int ret = ulzma(dest, dest_len, src, src_len);
                if (ret < 0)
                    return;
                src_len = ret;
            } else {
                dprintf(1, "No support for compression type %x\n"
                        , seg->compression);
                return;
            }
            if (dest_len > src_len)
                memset(dest + src_len, 0, dest_len - src_len);
            break;
        }
        seg++;
    }
}

// Register payloads in "img/" directory with boot system.
void
cbfs_payload_setup(void)
{
    if (!CONFIG_COREBOOT_FLASH)
        return;
    struct romfile_s *file = NULL;
    for (;;) {
        file = romfile_findprefix("img/", file);
        if (!file)
            break;
        struct cbfs_romfile_s *cfile;
        cfile = container_of(file, struct cbfs_romfile_s, file);
        const char *filename = file->name;
        char *desc = znprintf(MAXDESCSIZE, "Payload [%s]", &filename[4]);
        boot_add_cbfs(cfile->fhdr, desc, bootprio_find_named_rom(filename, 0));
    }
}
