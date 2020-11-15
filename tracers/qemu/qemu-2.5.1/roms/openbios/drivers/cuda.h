#include "adb_bus.h"

struct cuda_t {
	phys_addr_t base;
	adb_bus_t *adb_bus;
};
typedef struct cuda_t cuda_t;

enum {
	CHARDEV_KBD = 0,
	CHARDEV_MOUSE,
	CHARDEV_SERIAL,
	CHARDEV_DISPLAY,
	CHARDEV_LAST,
};

cuda_t *cuda_init (const char *path, phys_addr_t base);
