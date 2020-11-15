#include "romfile_loader.h"
#include "byteorder.h" // leXX_to_cpu/cpu_to_leXX
#include "util.h" // checksum
#include "string.h" // strcmp
#include "romfile.h" // struct romfile_s
#include "malloc.h" // Zone*, _malloc
#include "output.h" // warn_*

struct romfile_loader_file {
    struct romfile_s *file;
    void *data;
};
struct romfile_loader_files {
    int nfiles;
    struct romfile_loader_file files[];
};

static struct romfile_loader_file *
romfile_loader_find(const char *name,
                    struct romfile_loader_files *files)
{
    int i;
    if (name[ROMFILE_LOADER_FILESZ - 1])
        return NULL;
    for (i = 0; i < files->nfiles; ++i)
        if (!strcmp(files->files[i].file->name, name))
            return &files->files[i];
    return NULL;
}

static void romfile_loader_allocate(struct romfile_loader_entry_s *entry,
                                    struct romfile_loader_files *files)
{
    struct zone_s *zone;
    struct romfile_loader_file *file = &files->files[files->nfiles];
    void *data;
    int ret;
    unsigned alloc_align = le32_to_cpu(entry->alloc_align);

    if (alloc_align & (alloc_align - 1))
        goto err;

    switch (entry->alloc_zone) {
        case ROMFILE_LOADER_ALLOC_ZONE_HIGH:
            zone = &ZoneHigh;
            break;
        case ROMFILE_LOADER_ALLOC_ZONE_FSEG:
            zone = &ZoneFSeg;
            break;
        default:
            goto err;
    }
    if (alloc_align < MALLOC_MIN_ALIGN)
        alloc_align = MALLOC_MIN_ALIGN;
    if (entry->alloc_file[ROMFILE_LOADER_FILESZ - 1])
        goto err;
    file->file = romfile_find(entry->alloc_file);
    if (!file->file || !file->file->size)
        return;
    data = _malloc(zone, file->file->size, alloc_align);
    if (!data) {
        warn_noalloc();
        return;
    }
    ret = file->file->copy(file->file, data, file->file->size);
    if (ret != file->file->size)
        goto file_err;
    file->data = data;
    files->nfiles++;
    return;

file_err:
    free(data);
err:
    warn_internalerror();
}

static void romfile_loader_add_pointer(struct romfile_loader_entry_s *entry,
                                       struct romfile_loader_files *files)
{
    struct romfile_loader_file *dest_file;
    struct romfile_loader_file *src_file;
    unsigned offset = le32_to_cpu(entry->pointer_offset);
    u64 pointer = 0;

    dest_file = romfile_loader_find(entry->pointer_dest_file, files);
    src_file = romfile_loader_find(entry->pointer_src_file, files);

    if (!dest_file || !src_file || !dest_file->data || !src_file->data ||
        offset + entry->pointer_size < offset ||
        offset + entry->pointer_size > dest_file->file->size ||
        entry->pointer_size < 1 || entry->pointer_size > 8 ||
        entry->pointer_size & (entry->pointer_size - 1))
        goto err;

    memcpy(&pointer, dest_file->data + offset, entry->pointer_size);
    pointer = le64_to_cpu(pointer);
    pointer += (unsigned long)src_file->data;
    pointer = cpu_to_le64(pointer);
    memcpy(dest_file->data + offset, &pointer, entry->pointer_size);

    return;
err:
    warn_internalerror();
}

static void romfile_loader_add_checksum(struct romfile_loader_entry_s *entry,
                                        struct romfile_loader_files *files)
{
    struct romfile_loader_file *file;
    unsigned offset = le32_to_cpu(entry->cksum_offset);
    unsigned start = le32_to_cpu(entry->cksum_start);
    unsigned len = le32_to_cpu(entry->cksum_length);
    u8 *data;

    file = romfile_loader_find(entry->cksum_file, files);

    if (!file || !file->data || offset >= file->file->size ||
        start + len < start || start + len > file->file->size)
        goto err;

    data = file->data + offset;
    *data -= checksum(file->data + start, len);

    return;
err:
    warn_internalerror();
}

int romfile_loader_execute(const char *name)
{
    struct romfile_loader_entry_s *entry;
    int size, offset = 0, nfiles;
    struct romfile_loader_files *files;
    void *data = romfile_loadfile(name, &size);
    if (!data)
        return -1;

    if (size % sizeof(*entry)) {
        warn_internalerror();
        goto err;
    }

    /* (over)estimate the number of files to load. */
    nfiles = size / sizeof(*entry);
    files = malloc_tmp(sizeof(*files) + nfiles * sizeof(files->files[0]));
    if (!files) {
        warn_noalloc();
        goto err;
    }
    files->nfiles = 0;

    for (offset = 0; offset < size; offset += sizeof(*entry)) {
        entry = data + offset;
        switch (le32_to_cpu(entry->command)) {
                case ROMFILE_LOADER_COMMAND_ALLOCATE:
                        romfile_loader_allocate(entry, files);
                        break;
                case ROMFILE_LOADER_COMMAND_ADD_POINTER:
                        romfile_loader_add_pointer(entry, files);
                        break;
                case ROMFILE_LOADER_COMMAND_ADD_CHECKSUM:
                        romfile_loader_add_checksum(entry, files);
                default:
                        /* Skip commands that we don't recognize. */
                        break;
        }
    }

    free(files);
    free(data);
    return 0;

err:
    free(data);
    return -1;
}
