#ifndef __ATA_H
#define __ATA_H

#include "block.h" // struct drive_s
#include "config.h" // CONFIG_MAX_ATA_INTERFACES
#include "types.h" // u8

struct ata_channel_s {
    u16 iobase1;
    u16 iobase2;
    u16 iomaster;
    u8  irq;
    u8  chanid;
    int pci_bdf;
    struct pci_device *pci_tmp;
};

struct atadrive_s {
    struct drive_s drive;
    struct ata_channel_s *chan_gf;
    u8 slave;
};

// ata.c
char *ata_extract_model(char *model, u32 size, u16 *buffer);
int ata_extract_version(u16 *buffer);
int cdrom_read(struct disk_op_s *op);
int atapi_cmd_data(struct disk_op_s *op, void *cdbcmd, u16 blocksize);
void ata_setup(void);
int process_ata_op(struct disk_op_s *op);

#define PORT_ATA2_CMD_BASE     0x0170
#define PORT_ATA1_CMD_BASE     0x01f0
#define PORT_ATA2_CTRL_BASE    0x0374
#define PORT_ATA1_CTRL_BASE    0x03f4

// Global defines -- ATA register and register bits.
// command block & control block regs
#define ATA_CB_DATA  0   // data reg         in/out pio_base_addr1+0
#define ATA_CB_ERR   1   // error            in     pio_base_addr1+1
#define ATA_CB_FR    1   // feature reg         out pio_base_addr1+1
#define ATA_CB_SC    2   // sector count     in/out pio_base_addr1+2
#define ATA_CB_SN    3   // sector number    in/out pio_base_addr1+3
#define ATA_CB_CL    4   // cylinder low     in/out pio_base_addr1+4
#define ATA_CB_CH    5   // cylinder high    in/out pio_base_addr1+5
#define ATA_CB_DH    6   // device head      in/out pio_base_addr1+6
#define ATA_CB_STAT  7   // primary status   in     pio_base_addr1+7
#define ATA_CB_CMD   7   // command             out pio_base_addr1+7

#define ATA_CB_ASTAT 2   // alternate status in     pio_base_addr2+2
#define ATA_CB_DC    2   // device control      out pio_base_addr2+2
#define ATA_CB_DA    3   // device address   in     pio_base_addr2+3

#define ATA_CB_ER_ICRC 0x80    // ATA Ultra DMA bad CRC
#define ATA_CB_ER_BBK  0x80    // ATA bad block
#define ATA_CB_ER_UNC  0x40    // ATA uncorrected error
#define ATA_CB_ER_MC   0x20    // ATA media change
#define ATA_CB_ER_IDNF 0x10    // ATA id not found
#define ATA_CB_ER_MCR  0x08    // ATA media change request
#define ATA_CB_ER_ABRT 0x04    // ATA command aborted
#define ATA_CB_ER_NTK0 0x02    // ATA track 0 not found
#define ATA_CB_ER_NDAM 0x01    // ATA address mark not found

#define ATA_CB_ER_P_SNSKEY 0xf0   // ATAPI sense key (mask)
#define ATA_CB_ER_P_MCR    0x08   // ATAPI Media Change Request
#define ATA_CB_ER_P_ABRT   0x04   // ATAPI command abort
#define ATA_CB_ER_P_EOM    0x02   // ATAPI End of Media
#define ATA_CB_ER_P_ILI    0x01   // ATAPI Illegal Length Indication

// ATAPI Interrupt Reason bits in the Sector Count reg (CB_SC)
#define ATA_CB_SC_P_TAG    0xf8   // ATAPI tag (mask)
#define ATA_CB_SC_P_REL    0x04   // ATAPI release
#define ATA_CB_SC_P_IO     0x02   // ATAPI I/O
#define ATA_CB_SC_P_CD     0x01   // ATAPI C/D

// bits 7-4 of the device/head (CB_DH) reg
#define ATA_CB_DH_DEV0 0xa0    // select device 0
#define ATA_CB_DH_DEV1 0xb0    // select device 1
#define ATA_CB_DH_LBA 0x40    // use LBA

// status reg (CB_STAT and CB_ASTAT) bits
#define ATA_CB_STAT_BSY  0x80  // busy
#define ATA_CB_STAT_RDY  0x40  // ready
#define ATA_CB_STAT_DF   0x20  // device fault
#define ATA_CB_STAT_WFT  0x20  // write fault (old name)
#define ATA_CB_STAT_SKC  0x10  // seek complete
#define ATA_CB_STAT_SERV 0x10  // service
#define ATA_CB_STAT_DRQ  0x08  // data request
#define ATA_CB_STAT_CORR 0x04  // corrected
#define ATA_CB_STAT_IDX  0x02  // index
#define ATA_CB_STAT_ERR  0x01  // error (ATA)
#define ATA_CB_STAT_CHK  0x01  // check (ATAPI)

// device control reg (CB_DC) bits
#define ATA_CB_DC_HD15   0x08  // bit should always be set to one
#define ATA_CB_DC_SRST   0x04  // soft reset
#define ATA_CB_DC_NIEN   0x02  // disable interrupts

// Most mandtory and optional ATA commands (from ATA-3),
#define ATA_CMD_NOP                          0x00
#define ATA_CMD_CFA_REQUEST_EXT_ERR_CODE     0x03
#define ATA_CMD_DEVICE_RESET                 0x08
#define ATA_CMD_RECALIBRATE                  0x10
#define ATA_CMD_READ_SECTORS                 0x20
#define ATA_CMD_READ_SECTORS_EXT             0x24
#define ATA_CMD_READ_DMA_EXT                 0x25
#define ATA_CMD_READ_DMA_QUEUED_EXT          0x26
#define ATA_CMD_READ_NATIVE_MAX_ADDRESS_EXT  0x27
#define ATA_CMD_READ_MULTIPLE_EXT            0x29
#define ATA_CMD_READ_LOG_EXT                 0x2F
#define ATA_CMD_WRITE_SECTORS                0x30
#define ATA_CMD_WRITE_SECTORS_EXT            0x34
#define ATA_CMD_WRITE_DMA_EXT                0x35
#define ATA_CMD_WRITE_DMA_QUEUED_EXT         0x36
#define ATA_CMD_SET_MAX_ADDRESS_EXT          0x37
#define ATA_CMD_CFA_WRITE_SECTORS_WO_ERASE   0x38
#define ATA_CMD_WRITE_MULTIPLE_EXT           0x39
#define ATA_CMD_WRITE_VERIFY                 0x3C
#define ATA_CMD_WRITE_LOG_EXT                0x3F
#define ATA_CMD_READ_VERIFY_SECTORS          0x40
#define ATA_CMD_READ_VERIFY_SECTORS_EXT      0x42
#define ATA_CMD_FORMAT_TRACK                 0x50
#define ATA_CMD_SEEK                         0x70
#define ATA_CMD_CFA_TRANSLATE_SECTOR         0x87
#define ATA_CMD_EXECUTE_DEVICE_DIAGNOSTIC    0x90
#define ATA_CMD_INITIALIZE_DEVICE_PARAMETERS 0x91
#define ATA_CMD_STANDBY_IMMEDIATE2           0x94
#define ATA_CMD_IDLE_IMMEDIATE2              0x95
#define ATA_CMD_STANDBY2                     0x96
#define ATA_CMD_IDLE2                        0x97
#define ATA_CMD_CHECK_POWER_MODE2            0x98
#define ATA_CMD_SLEEP2                       0x99
#define ATA_CMD_PACKET                       0xA0
#define ATA_CMD_IDENTIFY_PACKET_DEVICE       0xA1
#define ATA_CMD_CFA_ERASE_SECTORS            0xC0
#define ATA_CMD_READ_MULTIPLE                0xC4
#define ATA_CMD_WRITE_MULTIPLE               0xC5
#define ATA_CMD_SET_MULTIPLE_MODE            0xC6
#define ATA_CMD_READ_DMA_QUEUED              0xC7
#define ATA_CMD_READ_DMA                     0xC8
#define ATA_CMD_WRITE_DMA                    0xCA
#define ATA_CMD_WRITE_DMA_QUEUED             0xCC
#define ATA_CMD_CFA_WRITE_MULTIPLE_WO_ERASE  0xCD
#define ATA_CMD_STANDBY_IMMEDIATE            0xE0
#define ATA_CMD_IDLE_IMMEDIATE               0xE1
#define ATA_CMD_STANDBY                      0xE2
#define ATA_CMD_IDLE                         0xE3
#define ATA_CMD_READ_BUFFER                  0xE4
#define ATA_CMD_CHECK_POWER_MODE             0xE5
#define ATA_CMD_SLEEP                        0xE6
#define ATA_CMD_FLUSH_CACHE                  0xE7
#define ATA_CMD_WRITE_BUFFER                 0xE8
#define ATA_CMD_IDENTIFY_DEVICE              0xEC
#define ATA_CMD_SET_FEATURES                 0xEF
#define ATA_CMD_READ_NATIVE_MAX_ADDRESS      0xF8
#define ATA_CMD_SET_MAX                      0xF9

#endif // ata.h
