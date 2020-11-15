
#ifndef __PLUGINS_H
#define __PLUGINS_H

#include "asm/types.h"

struct io_ops {
	u8  (*inb)(u32 reg);
	u16 (*inw)(u32 reg);
	u32 (*inl)(u32 reg);
	void (*outb)(u32 reg, u8 val);
	void (*outw)(u32 reg, u16 val);
	void (*outl)(u32 reg, u32 val);
};
typedef struct io_ops io_ops_t;

extern unsigned char *plugindir;

#define PLUGIN_DEPENDENCIES(x...) const char *plugin_deps[]={ x, NULL };
#define PLUGIN_AUTHOR(author)     const char *plugin_author=author;
#define PLUGIN_LICENSE(license)   const char *plugin_license=license;
#define PLUGIN_DESCRIPTION(desc)  const char *plugin_description=desc;

int register_iorange(const char *name, io_ops_t *ops,
				unsigned int rstart, unsigned int rend);
io_ops_t *find_iorange(u32 reg);

int load_plugin(const char *plugin_name);
int is_loaded(const char *plugin_name);

#endif
