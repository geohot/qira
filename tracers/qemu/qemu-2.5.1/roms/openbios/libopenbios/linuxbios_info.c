/* Adapted from Etherboot 5.1.8 */

#include "config.h"
#include "sysinclude.h"
#include "asm/types.h"
#include "asm/io.h"
#include "linuxbios.h"
#include "libopenbios/ipchecksum.h"
#include "libopenbios/sys_info.h"

#ifdef CONFIG_DEBUG_BOOT
#define debug printk
#else
#define debug(x...)
#endif

#define for_each_lbrec(head, rec) \
	for(rec = (struct lb_record *)(((char *)head) + sizeof(*head)); \
		(((char *)rec) < (((char *)head) + sizeof(*head) + head->table_bytes))  && \
		(rec->size >= 1) && \
		((((char *)rec) + rec->size) <= (((char *)head) + sizeof(*head) + head->table_bytes)); \
		rec = (struct lb_record *)(((char *)rec) + rec->size))

static void convert_memmap(struct lb_memory *lbmem, struct sys_info *info)
{
    int lbcount;
    int i;

    lbcount = lbmem->size / sizeof(struct lb_memory_range);
    info->memrange = malloc(lbcount * sizeof(struct memrange));
    info->n_memranges = 0;
    for (i = 0; i < lbcount; i++) {
	debug("%#016llx %#016llx %d\n",
              (long long)lbmem->map[i].start, (long long)lbmem->map[i].size,
              (int) lbmem->map[i].type);
	if (lbmem->map[i].type != LB_MEM_RAM)
	    continue;
	info->memrange[info->n_memranges].base = lbmem->map[i].start;
	info->memrange[info->n_memranges].size = lbmem->map[i].size;
	info->n_memranges++;
    }
}

static int read_lbtable(struct lb_header *head, struct sys_info *info)
{
	int retval = 0;

	/* Read linuxbios tables... */
	struct lb_record *rec;

	for_each_lbrec(head, rec) {
		switch(rec->tag) {
		case LB_TAG_MEMORY:
			convert_memmap((struct lb_memory *) rec, info);
			retval = 1;
			break;
		};
	}
	return retval;
}

static unsigned long count_lb_records(void *start, unsigned long length)
{
	struct lb_record *rec;
	void *end;
	unsigned long count;
	count = 0;
	end = ((char *)start) + length;
	for(rec = start; ((void *)rec < end) &&
		((signed long)rec->size <=
                 ((signed long)end - (signed long)rec));
		rec = (void *)(((char *)rec) + rec->size)) {
		count++;
	}
	return count;
}

static int find_lb_table(void *start, void *end, struct lb_header **result)
{
	unsigned char *ptr;
	/* For now be stupid.... */
	for(ptr = start; (void *)ptr < end; ptr += 16) {
		struct lb_header *head = (struct lb_header *)ptr;
		if (	(head->signature[0] != 'L') ||
			(head->signature[1] != 'B') ||
			(head->signature[2] != 'I') ||
			(head->signature[3] != 'O')) {
			continue;
		}
		if (head->header_bytes != sizeof(*head))
			continue;
		debug("Found canidate at: %p\n", head);
		if (ipchksum((uint16_t *)head, sizeof(*head)) != 0)
			continue;
		debug("header checksum o.k.\n");
		if (ipchksum((uint16_t *)(ptr + sizeof(*head)), head->table_bytes) !=
			head->table_checksum) {
			continue;
		}
		debug("table checksum o.k.\n");
		if (count_lb_records(ptr + sizeof(*head), head->table_bytes) !=
			head->table_entries) {
			continue;
		}
		debug("record count o.k.\n");
		*result = head;
		return 1;
	};
	return 0;
}

void collect_linuxbios_info(struct sys_info *info)
{
	struct lb_header *lb_table;
	int found;
	debug("Searching for LinuxBIOS tables...\n");
	found = 0;
	if (!found) {
		found = find_lb_table(phys_to_virt(0x00000), phys_to_virt(0x01000), &lb_table);
	}
	if (!found) {
		found = find_lb_table(phys_to_virt(0xf0000), phys_to_virt(0x100000), &lb_table);
	}
	if (!found)
		return;

	debug("Found LinuxBIOS table at: %p\n", lb_table);
	info->firmware = "LinuxBIOS";
	read_lbtable(lb_table, info);
}
