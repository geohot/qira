typedef struct pci_config_t pci_config_t;

struct pci_config_t {
	char path[256];
	uint32_t dev;		/* bus, dev, fn */
	uint32_t regions[7];
	uint32_t assigned[7];
	uint32_t sizes[7];
	int irq_pin;
	int irq_line;
	u32 primary_bus;
	u32 secondary_bus;
	u32 subordinate_bus;
};

typedef struct pci_dev_t pci_dev_t;
struct pci_dev_t {
    uint16_t vendor;
    uint16_t product;
    const char *type;
    const char *name;
    const char *model;
    const char *compat;
    int acells;
    int scells;
    int icells;
    int (*config_cb)(const pci_config_t *config);
    const void *private;
};

extern int ide_config_cb2(const pci_config_t *config);
extern int eth_config_cb(const pci_config_t *config);
extern int macio_heathrow_config_cb(const pci_config_t *config);
extern int macio_keylargo_config_cb(const pci_config_t *config);
extern int vga_config_cb(const pci_config_t *config);
extern int host_config_cb(const pci_config_t *config);
extern int sabre_config_cb(const pci_config_t *config);
extern int bridge_config_cb(const pci_config_t *config);
extern int ebus_config_cb(const pci_config_t *config);
extern int i82378_config_cb(const pci_config_t *config);
extern int usb_ohci_config_cb(const pci_config_t *config);

static inline int pci_compat_len(const pci_dev_t *dev)
{
	int len, ret;
	const char *path = dev->compat;
	ret = 0;
	while ((len = strlen(path)) != 0) {
		ret += len + 1;
		path += len + 1;
	}
	return ret;
}

extern const pci_dev_t *pci_find_device(uint8_t class, uint8_t subclass,
					uint8_t iface, uint16_t vendor,
					uint16_t product);
