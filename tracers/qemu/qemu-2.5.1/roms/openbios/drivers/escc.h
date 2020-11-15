
#define IO_ESCC_SIZE    0x00001000
#define IO_ESCC_OFFSET  0x00013000
#define IO_ESCC_LEGACY_SIZE    0x00001000
#define IO_ESCC_LEGACY_OFFSET  0x00012000

#define ZS_REGS         8

void escc_init(const char *path, phys_addr_t addr);
void ob_zs_init(phys_addr_t base, uint64_t offset, int intr, int slave,
                int keyboard);
