/*
 * <bios.h>
 *
 * header for Open Hack'Ware
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
#if !defined (__BIOS_H__)
#define __BIOS_H__

#define USE_OPENFIRMWARE
//#define DEBUG_BIOS 1

#define BIOS_VERSION "0.4.1"

#define DSISR 18
#define DAR   19
#define SRR0  26
#define SRR1  27

#define _tostring(s) #s
#define stringify(s) _tostring(s)

#if !defined (ASSEMBLY_CODE)

#ifdef DEBUG_BIOS
#define DPRINTF(fmt, args...) do { dprintf(fmt , ##args); } while (0)
#else
#define DPRINTF(fmt, args...) do { } while (0)
#endif
#define ERROR(fmt, args...) do { printf("ERROR: " fmt , ##args); } while (0)
#define MSG(fmt, args...) do { printf(fmt , ##args); } while (0)

#define offsetof(_struct, field)                                      \
({                                                                    \
    typeof(_struct) __tmp_struct;                                     \
    int __off;                                                        \
    __off = (char *)(&__tmp_struct.field) - (char *)(&__tmp_struct);  \
    __off;                                                            \
})

#define unused __attribute__ (( unused)) 

/* Useful macro in C code */
#define MTSPR(num, value)                                            \
__asm__ __volatile__ ("mtspr " stringify(num) ", %0" :: "r"(value));

/* Architectures */
enum {
    ARCH_PREP = 0,
    ARCH_CHRP,
    ARCH_MAC99,
    ARCH_POP,
    ARCH_HEATHROW,
};

/* Hardware definition(s) */
extern uint32_t isa_io_base;
#define ISA_IO_BASE 0x80000000
extern int arch;

/*****************************************************************************/
/* From start.S : BIOS start code and asm helpers */
void transfer_handler (void *residual, void *load_addr,
                       void *OF_entry, void *bootinfos,
                       void *cmdline, void *not_used,
                       void *nip, void *stack_base);
void bug (void);

/* PPC helpers */
uint32_t mfmsr (void);
void mtmsr (uint32_t msr);
uint32_t mfpvr (void);
void mftb (uint32_t *tb);
void MMU_on (void);
void MMU_off (void);
/* IO helpers */
uint32_t inb (uint16_t port);
void outb (uint16_t port, uint32_t val);
uint32_t inw (uint16_t port);
void outw (uint16_t port, uint32_t val);
uint32_t inl (uint16_t port);
void outl (uint16_t port, uint32_t val);
void eieio (void);
/* Misc helpers */
uint16_t ldswap16 (uint16_t *addr);
void stswap16 (void *addr, uint16_t val);
uint32_t ldswap32 (uint32_t *addr);
void stswap32 (void *addr, uint32_t val);
void mul64 (uint32_t *ret, uint32_t a, uint32_t b);
void add64 (uint32_t *ret, uint32_t *a, uint32_t *b);

typedef struct jmp_buf {
    uint32_t gpr[32];
    uint32_t lr;
    uint32_t ctr;
    uint32_t xer;
    uint32_t ccr;
} jmp_buf;
int setjmp (jmp_buf env);
void longjmp (jmp_buf env);

/*****************************************************************************/
/* PCI BIOS                                                                  */
typedef struct pci_common_t pci_common_t;
typedef struct pci_host_t pci_host_t;
typedef struct pci_device_t pci_device_t;
typedef struct pci_bridge_t pci_bridge_t;
typedef struct pci_ops_t pci_ops_t;
typedef union pci_u_t pci_u_t;

typedef struct pci_dev_t pci_dev_t;
struct pci_dev_t {
    uint16_t vendor;
    uint16_t product;
    const unsigned char *type;
    const unsigned char *name;
    const unsigned char *model;
    const unsigned char *compat;
    int acells;
    int scells;
    int icells;
    int (*config_cb)(pci_device_t *device);
    const void *private;
};

pci_host_t *pci_init (void);
void pci_get_mem_range (pci_host_t *host, uint32_t *start, uint32_t *len);

/*****************************************************************************/
/* nvram.c : NVRAM management routines */
typedef struct nvram_t nvram_t;
extern nvram_t *nvram;

uint8_t NVRAM_read (nvram_t *nvram, uint32_t addr);
void NVRAM_write (nvram_t *nvram, uint32_t addr, uint8_t value);
uint16_t NVRAM_get_size (nvram_t *nvram);
int NVRAM_format (nvram_t *nvram);
nvram_t *NVRAM_get_config (uint32_t *RAM_size, int *boot_device,
                           void **boot_image, uint32_t *boot_size,
                           void **cmdline, uint32_t *cmdline_size,
                           void **ramdisk, uint32_t *ramdisk_size);

/*****************************************************************************/
/* bloc.c : bloc devices management */
typedef struct pos_t {
    uint32_t bloc;
    uint32_t offset;
} pos_t;

typedef struct bloc_device_t bloc_device_t;
typedef struct part_t part_t;
typedef struct fs_t fs_t;

bloc_device_t *bd_open (int device);
int bd_seek (bloc_device_t *bd, uint32_t bloc, uint32_t pos);
int bd_read (bloc_device_t *bd, void *buffer, int len);
int bd_write (bloc_device_t *bd, const void *buffer, int len);
#define _IOCTL(a, b) (((a) << 16) | (b))
#define MEM_SET_ADDR _IOCTL('M', 0x00)
#define MEM_SET_SIZE _IOCTL('M', 0x01)
int bd_ioctl (bloc_device_t *bd, int func, void *args);
uint32_t bd_seclen (bloc_device_t *bd);
void bd_close (bloc_device_t *bd);
void bd_reset_all(void);
uint32_t bd_seclen (bloc_device_t *bd);
uint32_t bd_maxbloc (bloc_device_t *bd);
void bd_sect2CHS (bloc_device_t *bd, uint32_t secnum,
                  int *cyl, int *head, int *sect);
uint32_t bd_CHS2sect (bloc_device_t *bd,
                      int cyl, int head, int sect);
part_t *bd_probe (int boot_device);
bloc_device_t *bd_get (int device);
void bd_put (bloc_device_t *bd);
void bd_set_boot_part (bloc_device_t *bd, part_t *partition, int partnum);
part_t **_bd_parts (bloc_device_t *bd);

void ide_pci_pc_register (uint32_t io_base0, uint32_t io_base1,
                          uint32_t io_base2, uint32_t io_base3,
                          void *OF_private0, void *OF_private1);
void ide_pci_pmac_register (uint32_t io_base0, uint32_t io_base1,
                            void *OF_private);

/*****************************************************************************/
/* part.c : partitions management */
enum part_flags_t {
    PART_TYPE_RAW     = 0x0000,
    PART_TYPE_PREP    = 0x0001,
    PART_TYPE_APPLE   = 0x0002,
    PART_TYPE_ISO9660 = 0x0004,
    PART_FLAG_DUMMY   = 0x0010,
    PART_FLAG_DRIVER  = 0x0020,
    PART_FLAG_PATCH   = 0x0040,
    PART_FLAG_FS      = 0x0080,
    PART_FLAG_BOOT    = 0x0100,
};

enum {
    PART_PREP = 0x01,
    PART_CHRP = 0x02,
};

part_t *part_open (bloc_device_t *bd,
                   uint32_t start, uint32_t size, uint32_t spb);
int part_seek (part_t *part, uint32_t bloc, uint32_t pos);
int part_read (part_t *part, void *buffer, int len);
int part_write (part_t *part, const void *buffer, int len);
void part_close (part_t *part);
uint32_t part_blocsize (part_t *part);
uint32_t part_flags (part_t *part);
uint32_t part_size (part_t *part);
fs_t *part_fs (part_t *part);

part_t *part_get (bloc_device_t *bd, int partnum);
part_t *part_probe (bloc_device_t *bd, int set_raw);
int part_set_boot_file (part_t *part, uint32_t start, uint32_t offset,
                        uint32_t size);

/*****************************************************************************/
/* fs.c : file system management */
typedef struct dir_t dir_t;
typedef struct dirent_t dirent_t;
typedef struct inode_t inode_t;

struct dirent_t {
    dir_t *dir;
    inode_t *inode;
    const unsigned char *dname;
};

enum {
    INODE_TYPE_UNKNOWN = 0x00FF,
    INODE_TYPE_DIR     = 0x0000,
    INODE_TYPE_FILE    = 0x0001,
    INODE_TYPE_OTHER   = 0x0002,
    INODE_TYPE_MASK    = 0x00FF,
    INODE_FLAG_EXEC    = 0x0100,
    INODE_FLAG_BOOT    = 0x0200,
    INODE_FLAG_MASK    = 0xFF00,
};

/* probe a filesystem from a partition */
fs_t *fs_probe (part_t *part, int set_raw);
part_t *fs_part (fs_t *fs);
/* Recurse thru directories */
dir_t *fs_opendir (fs_t *fs, const unsigned char *name);
dirent_t *fs_readdir (dir_t *dir);
unsigned char *fs_get_path (dirent_t *dirent);
void fs_closedir (dir_t *dir);
/* Play with files */
inode_t *fs_open (fs_t *fs, const unsigned char *name);
int fs_seek (inode_t *inode, uint32_t bloc, uint32_t pos);
int fs_read (inode_t *inode, void *buffer, int len);
int fs_write (inode_t *inode, const void *buffer, unused int len);
void fs_close (inode_t *inode);
uint32_t fs_get_type (fs_t *fs);
uint32_t fs_inode_get_type (inode_t *inode);
uint32_t fs_inode_get_flags (inode_t *inode);
part_t *fs_inode_get_part (inode_t *inode);

/* Bootfile */
unsigned char *fs_get_boot_dirname (fs_t *fs);
inode_t *fs_get_bootfile (fs_t *fs);
int fs_raw_set_bootfile (part_t *part,
                         uint32_t start_bloc, uint32_t start_offset,
                         uint32_t size_bloc, uint32_t size_offset);

/*****************************************************************************/
/* file.c : file management */
#define DEFAULT_LOAD_DEST 0x00100000

uint32_t file_seek (inode_t *file, uint32_t pos);

/* Executable files loader */
int bootfile_load (void **dest, void **entry, void **end,
                   part_t *part, int type, const unsigned char *fname,
                   uint32_t offset);

/*****************************************************************************/
/* char.c : char devices */
typedef struct chardev_t chardev_t;
typedef struct cops_t cops_t;

struct cops_t {
    int (*open)(void *private);
    int (*close)(void *private);
    int (*read)(void *private);
    int (*write)(void *private, int c);
    /* Won't implement seek for now */
};

enum {
    CHARDEV_KBD = 0,
    CHARDEV_MOUSE,
    CHARDEV_SERIAL,
    CHARDEV_DISPLAY,
    CHARDEV_LAST,
};

int chardev_register (int type, cops_t *ops, void *private);
int chardev_open (chardev_t *dev);
int chardev_close (chardev_t *dev);
int chardev_read (chardev_t *dev, void *buffer, int maxlen);
int chardev_write (chardev_t *dev, const void *buffer, int maxlen);
int chardev_type (chardev_t *dev);

/* Console driver */
int console_open (void);
int console_read (void *buffer, int maxlen);
int console_write (const void *buffer, int len);
void console_close (void);

/* PC serial port */
#define SERIAL_OUT_PORT (0x03F8)
int pc_serial_register (uint16_t base);

/* CUDA host */
typedef struct cuda_t cuda_t;
cuda_t *cuda_init (uint32_t base);
void cuda_reset (cuda_t *cuda);

/*****************************************************************************/
/* vga.c : VGA console */
extern unsigned long vga_fb_phys_addr;
extern int vga_fb_width;
extern int vga_fb_height;
extern int vga_fb_linesize;
extern int vga_fb_bpp;
extern int vga_fb_depth;
void vga_prep_init(void);
void vga_set_address (uint32_t address);
void vga_set_mode(int width, int height, int depth);
void vga_set_palette(int i, unsigned int rgba);
#define RGBA(r, g, b, a) (((a) << 24) | ((r) << 16) | ((g) << 8) | (b))
#define RGB(r, g, b) RGBA(r, g, b, 0xff)
unsigned int vga_get_color(unsigned int rgba);

void vga_draw_buf (const void *buf, int buf_linesize,
                   int posx, int posy, int width, int height);
void vga_fill_rect (int posx, int posy, int width, int height, uint32_t color);
void vga_bitblt(int xs, int ys, int xd, int yd, int w, int h);
void vga_check_mode(int width, int height, int depth);

/* text primitives */
void vga_text_set_fgcol(unsigned int rgba);
void vga_text_set_bgcol(unsigned int rgba);
void vga_putcharxy(int x, int y, int ch,
                   unsigned int fgcol, unsigned int bgcol);
void vga_putchar(int ch);
void vga_puts(const char *s);

/*****************************************************************************/
/* bootinfos.c : build structures needed by kernels to boot */
void prepare_bootinfos (void *p, uint32_t memsize,
                        void *cmdline, void *initrd, uint32_t initrd_size);
void residual_build (void *p, uint32_t memsize,
                     uint32_t load_base, uint32_t load_size,
                     uint32_t last_alloc);

/*****************************************************************************/
/* of.c : Open-firmware emulation */
#define OF_NAMELEN_MAX 1024
#define OF_PROPLEN_MAX 256

int OF_init (void);
int OF_register_mb (const unsigned char *model, const unsigned char **compats);
int OF_register_cpu (const unsigned char *name, int num, uint32_t pvr,
                     uint32_t min_freq, uint32_t max_freq, uint32_t bus_freq,
                     uint32_t tb_freq, uint32_t reset_io);
#if 0
int OF_register_translations (int nb, OF_transl_t *translations);
#endif
uint32_t OF_claim_virt (uint32_t virt, uint32_t size, int *range);
int OF_register_memory (uint32_t memsize, uint32_t bios_size);
int OF_register_bootargs (const unsigned char *bootargs);
void *OF_register_pci_host (pci_dev_t *dev, uint16_t rev, uint32_t ccode,
                            uint32_t cfg_base, uint32_t cfg_len,
                            uint32_t mem_base, uint32_t mem_len,
                            uint32_t io_base, uint32_t io_len,
                            uint32_t rbase, uint32_t rlen,
                            uint16_t min_grant, uint16_t max_latency);
void *OF_register_pci_bridge (void *parent, pci_dev_t *dev,
                              uint32_t cfg_base, uint32_t cfg_len,
                              uint8_t devfn, uint8_t rev, uint32_t ccode,
                              uint16_t min_grant, uint16_t max_latency);
void *OF_register_pci_device (void *parent, pci_dev_t *dev,
                              uint8_t devfn, uint8_t rev, uint32_t ccode,
                              uint16_t min_grant, uint16_t max_latency);
void OF_finalize_pci_host (void *dev, int first_bus, int nb_busses);
void OF_finalize_pci_device (void *dev, uint8_t bus, uint8_t devfn,
                             uint32_t *regions, uint32_t *sizes,
                             int irq_line);
void OF_finalize_pci_macio (void *dev, uint32_t base_address, uint32_t size,
                            void *private_data);
void OF_finalize_pci_ide (void *dev, 
                          uint32_t io_base0, uint32_t io_base1,
                          uint32_t io_base2, uint32_t io_base3);
int OF_register_bus (const unsigned char *name, uint32_t address,
                     const unsigned char *type);
int OF_register_serial (const unsigned char *bus, const unsigned char *name,
                        uint32_t io_base, int irq);
int OF_register_stdio (const unsigned char *dev_in,
                       const unsigned char *dev_out);
void OF_vga_register (const unsigned char *name, unused uint32_t address,
                      int width, int height, int depth,
                      unsigned long vga_bios_addr, 
                      unsigned long vga_bios_size);
void *OF_blockdev_register (void *parent, void *private,
                            const unsigned char *type,
                            const unsigned char *name, int devnum,
                            const char *alias);
void OF_blockdev_set_boot_device (void *disk, int partnum,
                                  const unsigned char *file);

int OF_entry (void *p);
int OF_client_entry (void *p);
void RTAS_init (void);

/*****************************************************************************/
/* main.c : main BIOS code */
/* Memory management */
/* Memory areas */
extern uint32_t _data_start, _data_end;
extern uint32_t _OF_vars_start, _OF_vars_end;
extern uint32_t _sdata_start, _sdata_end;
extern uint32_t _ro_start, _ro_end;
extern uint32_t _RTAS_start, _RTAS_end;
extern uint32_t _RTAS_data_start, _RTAS_data_end;
extern uint32_t _bss_start, _bss_end;
extern uint32_t _ram_start;
extern const unsigned char *BIOS_str;
extern const unsigned char *copyright;
void *mem_align (int align);
void freep (void *p);

/* Endian-safe memory read/write */
static inline void put_be64 (void *addr, uint64_t l)
{
    *(uint64_t *)addr = l;
}

static inline uint64_t get_be64 (void *addr)
{
    return *(uint64_t *)addr;
}

static inline void put_le64 (void *addr, uint64_t l)
{
    uint32_t *p;

    p = addr;
    stswap32(p, l);
    stswap32(p + 1, l >> 32);
}

static inline uint64_t get_le64 (void *addr)
{
    uint64_t val;
    uint32_t *p;

    p = addr;
    val = ldswap32(p);
    val |= (uint64_t)ldswap32(p + 1) << 32;
    
    return val;
}

static inline void put_be32 (void *addr, uint32_t l)
{
    *(uint32_t *)addr = l;
}

static inline uint32_t get_be32 (void *addr)
{
    return *(uint32_t *)addr;
}

static inline void put_le32 (void *addr, uint32_t l)
{
    stswap32(addr, l);
}

static inline uint32_t get_le32 (void *addr)
{
    return ldswap32(addr);
}

static inline void put_be16 (void *addr, uint16_t l)
{
    *(uint16_t *)addr = l;
}

static inline uint16_t get_be16 (void *addr)
{
    return *(uint16_t *)addr;
}

static inline void put_le16 (void *addr, uint16_t l)
{
    stswap16(addr, l);
}

static inline uint16_t get_le16 (void *addr)
{
    return ldswap16(addr);
}

/* String functions */
long strtol (const unsigned char *str, unsigned char **end, int base);

int write_buf (const unsigned char *buf, int len);

/* Misc */
void usleep (uint32_t usec);
void sleep (int sec);
uint32_t crc32 (uint32_t crc, const uint8_t *p, int len);
void set_loadinfo (void *load_base, uint32_t size);
void set_check (int do_it);
void check_location (const void *buf, const char *func, const char *name);

static inline void pokeb (void *location, uint8_t val)
{
#ifdef DEBUG_BIOS
    check_location(location, __func__, "location");
#endif
    *((uint8_t *)location) = val;
}

static inline uint8_t peekb (void *location)
{
#ifdef DEBUG_BIOS
    check_location(location, __func__, "location");
#endif
    return *((uint8_t *)location);
}

static inline void pokew (void *location, uint16_t val)
{
#ifdef DEBUG_BIOS
    check_location(location, __func__, "location");
#endif
    *((uint8_t *)location) = val;
}

static inline uint16_t peekw (void *location)
{
#ifdef DEBUG_BIOS
    check_location(location, __func__, "location");
#endif
    return *((uint16_t *)location);
}

static inline void pokel (void *location, uint32_t val)
{
#ifdef DEBUG_BIOS
    check_location(location, __func__, "location");
#endif
    *((uint32_t *)location) = val;
}

static inline uint32_t peekl (void *location)
{
#ifdef DEBUG_BIOS
    check_location(location, __func__, "location");
#endif
    return *((uint32_t *)location);
}

/* Console */
int cs_write (const unsigned char *buf, int len);

#endif /* !defined (ASSEMBLY_CODE) */


#endif /* !defined (__BIOS_H__) */
