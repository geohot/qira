#include "config.h"
#include "libopenbios/bindings.h"
#include "libc/byteorder.h"
#include "libopenbios/ofmem.h"
#define NO_QEMU_PROTOS
#include "arch/common/fw_cfg.h"

#if !defined(CONFIG_SPARC64)
static volatile uint16_t *fw_cfg_cmd;
static volatile uint8_t *fw_cfg_data;

void
fw_cfg_read(uint16_t cmd, char *buf, unsigned int nbytes)
{
    unsigned int i;

    *fw_cfg_cmd = cmd;
    for (i = 0; i < nbytes; i++)
        buf[i] = *fw_cfg_data;
}
#else
// XXX depends on PCI bus location, should be removed
void
fw_cfg_read(uint16_t cmd, char *buf, unsigned int nbytes)
{
    unsigned int i;

    outw(cmd, CONFIG_FW_CFG_ADDR);
    for (i = 0; i < nbytes; i++)
        buf[i] = inb(CONFIG_FW_CFG_ADDR + 1);
}
#endif

uint64_t
fw_cfg_read_i64(uint16_t cmd)
{
    uint64_t buf;

    fw_cfg_read(cmd, (char *)&buf, sizeof(uint64_t));

    return __le64_to_cpu(buf);
}

uint32_t
fw_cfg_read_i32(uint16_t cmd)
{
    uint32_t buf;

    fw_cfg_read(cmd, (char *)&buf, sizeof(uint32_t));

    return __le32_to_cpu(buf);
}

uint16_t
fw_cfg_read_i16(uint16_t cmd)
{
    uint16_t buf;

    fw_cfg_read(cmd, (char *)&buf, sizeof(uint16_t));

    return __le16_to_cpu(buf);
}

void
fw_cfg_init(void)
{
#if defined(CONFIG_SPARC32)
    fw_cfg_cmd = (void *)ofmem_map_io(CONFIG_FW_CFG_ADDR, 2);
    fw_cfg_data = (uint8_t *)fw_cfg_cmd + 2;
#elif defined(CONFIG_SPARC64)
    // Nothing for the port version
#elif defined(CONFIG_PPC)
    fw_cfg_cmd = (void *)CONFIG_FW_CFG_ADDR;
    fw_cfg_data = (void *)(CONFIG_FW_CFG_ADDR + 2);
#endif
}
