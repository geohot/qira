#ifndef FW_CFG_H
#define FW_CFG_H

#define FW_CFG_SIGNATURE        0x00
#define FW_CFG_ID               0x01
#define FW_CFG_UUID             0x02
#define FW_CFG_RAM_SIZE         0x03
#define FW_CFG_NOGRAPHIC        0x04
#define FW_CFG_NB_CPUS          0x05
#define FW_CFG_MACHINE_ID       0x06
#define FW_CFG_KERNEL_ADDR      0x07
#define FW_CFG_KERNEL_SIZE      0x08
#define FW_CFG_KERNEL_CMDLINE   0x09
#define FW_CFG_INITRD_ADDR      0x0a
#define FW_CFG_INITRD_SIZE      0x0b
#define FW_CFG_BOOT_DEVICE      0x0c
#define FW_CFG_NUMA             0x0d
#define FW_CFG_BOOT_MENU        0x0e
#define FW_CFG_MAX_CPUS         0x0f
#define FW_CFG_KERNEL_ENTRY     0x10
#define FW_CFG_KERNEL_DATA      0x11
#define FW_CFG_INITRD_DATA      0x12
#define FW_CFG_CMDLINE_ADDR     0x13
#define FW_CFG_CMDLINE_SIZE     0x14
#define FW_CFG_CMDLINE_DATA     0x15
#define FW_CFG_SETUP_ADDR       0x16
#define FW_CFG_SETUP_SIZE       0x17
#define FW_CFG_SETUP_DATA       0x18
#define FW_CFG_FILE_DIR         0x19

#define FW_CFG_FILE_FIRST       0x20
#define FW_CFG_FILE_SLOTS       0x10
#define FW_CFG_MAX_ENTRY        (FW_CFG_FILE_FIRST+FW_CFG_FILE_SLOTS)

#define FW_CFG_WRITE_CHANNEL    0x4000
#define FW_CFG_ARCH_LOCAL       0x8000
#define FW_CFG_ENTRY_MASK       ~(FW_CFG_WRITE_CHANNEL | FW_CFG_ARCH_LOCAL)

#define FW_CFG_PPC_WIDTH        (FW_CFG_ARCH_LOCAL + 0x00)
#define FW_CFG_PPC_HEIGHT       (FW_CFG_ARCH_LOCAL + 0x01)
#define FW_CFG_PPC_DEPTH        (FW_CFG_ARCH_LOCAL + 0x02)
#define FW_CFG_PPC_TBFREQ       (FW_CFG_ARCH_LOCAL + 0x03)
#define FW_CFG_PPC_CLOCKFREQ    (FW_CFG_ARCH_LOCAL + 0x04)
#define FW_CFG_PPC_IS_KVM	(FW_CFG_ARCH_LOCAL + 0x05)
#define FW_CFG_PPC_KVM_HC	(FW_CFG_ARCH_LOCAL + 0x06)
#define FW_CFG_PPC_KVM_PID	(FW_CFG_ARCH_LOCAL + 0x07)
#define FW_CFG_PPC_NVRAM_ADDR	(FW_CFG_ARCH_LOCAL + 0x08)
#define FW_CFG_PPC_BUSFREQ      (FW_CFG_ARCH_LOCAL + 0x09)
#define FW_CFG_PPC_NVRAM_FLAT   (FW_CFG_ARCH_LOCAL + 0x0a)

#define FW_CFG_INVALID          0xffff

#ifndef NO_QEMU_PROTOS
typedef struct FWCfgFile {
    uint32_t  size;        /* file size */
    uint16_t  select;      /* write this to 0x510 to read it */
    uint16_t  reserved;
    char      name[56];
} FWCfgFile;

typedef struct FWCfgFiles {
    uint32_t  count;
    FWCfgFile f[];
} FWCfgFiles;

typedef void (*FWCfgCallback)(void *opaque, uint8_t *data);

typedef struct _FWCfgState FWCfgState;
int fw_cfg_add_bytes(FWCfgState *s, uint16_t key, uint8_t *data, uint32_t len);
int fw_cfg_add_i16(FWCfgState *s, uint16_t key, uint16_t value);
int fw_cfg_add_i32(FWCfgState *s, uint16_t key, uint32_t value);
int fw_cfg_add_i64(FWCfgState *s, uint16_t key, uint64_t value);
int fw_cfg_add_callback(FWCfgState *s, uint16_t key, FWCfgCallback callback,
                        void *callback_opaque, uint8_t *data, size_t len);
int fw_cfg_add_file(FWCfgState *s, const char *dir, const char *filename,
                    uint8_t *data, uint32_t len);
FWCfgState *fw_cfg_init(uint32_t ctl_port, uint32_t data_port,
                        target_phys_addr_t crl_addr, target_phys_addr_t data_addr);

#endif /* NO_QEMU_PROTOS */

#ifndef NO_OPENBIOS_PROTOS
void fw_cfg_read(uint16_t cmd, char *buf, unsigned int nbytes);
uint64_t fw_cfg_read_i64(uint16_t cmd);
uint32_t fw_cfg_read_i32(uint16_t cmd);
uint16_t fw_cfg_read_i16(uint16_t cmd);
void fw_cfg_init(void);
#endif /* NO_OPENBIOS_PROTOS */

#endif
