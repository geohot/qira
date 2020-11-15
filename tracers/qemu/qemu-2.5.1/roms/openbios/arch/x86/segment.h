
/* Segment indexes. Must match the gdt definition in segment.c. */
enum {
    NULL_SEG,
    FLAT_CODE,
    FLAT_DATA,
    RELOC_CODE,
    RELOC_DATA,
    NUM_SEG,
};

/* Values for segment selector register */
#define FLAT_CS (FLAT_CODE << 3)
#define FLAT_DS (FLAT_DATA << 3)
#define RELOC_CS (RELOC_CODE << 3)
#define RELOC_DS (RELOC_DATA << 3)

/* i386 segment descriptor */
struct segment_desc {
    unsigned short limit_0;
    unsigned short base_0;
    unsigned char base_16;
    unsigned char types;
    unsigned char flags;
    unsigned char base_24;
};

extern struct segment_desc gdt[NUM_SEG];

#define GDT_LIMIT ((NUM_SEG << 3) - 1)
