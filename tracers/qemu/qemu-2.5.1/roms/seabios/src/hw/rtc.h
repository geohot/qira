#ifndef __RTC_H
#define __RTC_H

#define PORT_CMOS_INDEX        0x0070
#define PORT_CMOS_DATA         0x0071

// PORT_CMOS_INDEX nmi disable bit
#define NMI_DISABLE_BIT 0x80

// Standard BIOS RTC chip entries
#define CMOS_RTC_SECONDS         0x00
#define CMOS_RTC_SECONDS_ALARM   0x01
#define CMOS_RTC_MINUTES         0x02
#define CMOS_RTC_MINUTES_ALARM   0x03
#define CMOS_RTC_HOURS           0x04
#define CMOS_RTC_HOURS_ALARM     0x05
#define CMOS_RTC_DAY_WEEK        0x06
#define CMOS_RTC_DAY_MONTH       0x07
#define CMOS_RTC_MONTH           0x08
#define CMOS_RTC_YEAR            0x09
#define CMOS_STATUS_A            0x0a
#define CMOS_STATUS_B            0x0b
#define CMOS_STATUS_C            0x0c
#define CMOS_STATUS_D            0x0d
#define CMOS_RESET_CODE          0x0f

// QEMU cmos config fields.  DO NOT ADD MORE.  (All new content should
// be passed via the fw_cfg "file" interface.)
#define CMOS_FLOPPY_DRIVE_TYPE   0x10
#define CMOS_DISK_DATA           0x12
#define CMOS_EQUIPMENT_INFO      0x14
#define CMOS_DISK_DRIVE1_TYPE    0x19
#define CMOS_DISK_DRIVE2_TYPE    0x1a
#define CMOS_DISK_DRIVE1_CYL     0x1b
#define CMOS_DISK_DRIVE2_CYL     0x24
#define CMOS_MEM_EXTMEM_LOW      0x30
#define CMOS_MEM_EXTMEM_HIGH     0x31
#define CMOS_CENTURY             0x32
#define CMOS_MEM_EXTMEM2_LOW     0x34
#define CMOS_MEM_EXTMEM2_HIGH    0x35
#define CMOS_BIOS_BOOTFLAG1      0x38
#define CMOS_BIOS_DISKTRANSFLAG  0x39
#define CMOS_BIOS_BOOTFLAG2      0x3d
#define CMOS_MEM_HIGHMEM_LOW     0x5b
#define CMOS_MEM_HIGHMEM_MID     0x5c
#define CMOS_MEM_HIGHMEM_HIGH    0x5d
#define CMOS_BIOS_SMP_COUNT      0x5f

// RTC register flags
#define RTC_A_UIP 0x80

#define RTC_B_SET  0x80
#define RTC_B_PIE  0x40
#define RTC_B_AIE  0x20
#define RTC_B_UIE  0x10
#define RTC_B_BIN  0x04
#define RTC_B_24HR 0x02
#define RTC_B_DSE  0x01

#ifndef __ASSEMBLY__

#include "types.h" // u8

// rtc.c
u8 rtc_read(u8 index);
void rtc_write(u8 index, u8 val);
void rtc_mask(u8 index, u8 off, u8 on);
int rtc_updating(void);
void rtc_setup(void);
void rtc_use(void);
void rtc_release(void);

#endif // !__ASSEMBLY__

#endif // rtc.h
