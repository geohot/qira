/* tag: plugin interface for openbios forth kernel
 *
 * Copyright (C) 2003, 2004 Stefan Reinauer
 *
 * See the file "COPYING" for further information about
 * the copyright and warranty status of this work.
 */

#include "sysinclude.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

#include "unix/plugins.h"

unsigned char *plugindir = "/usr/share/OpenBIOS/plugins";
#define PLUGINDIR  plugindir
#define PATHSIZE   256

#define CONFIG_DEBUG_PLUGINS

typedef struct iorange iorange_t;
struct iorange {
	const char *name;
	unsigned int start;
	unsigned int end;
	io_ops_t *ops;
	iorange_t *next;
};

static iorange_t *ioranges = NULL;

typedef struct plugin plugin_t;
struct plugin {
	const char *name;
	plugin_t *next;
};

static plugin_t *plugins = NULL;

io_ops_t *find_iorange(u32 reg)
{
	iorange_t *range = ioranges;
	while (range) {
		if (range->start <= reg && range->end >= reg)
			return range->ops;
		range = range->next;
	}
	return NULL;
}

int register_iorange(const char *name, io_ops_t * ops, unsigned int rstart,
		     unsigned int rend)
{
	iorange_t *newrange;

	/* intersection check */
	newrange = ioranges;
	while (newrange) {
		int fail = 0;
		/* new section swallows old section */
		if (newrange->start >= rstart && newrange->end <= rend)
			fail = -1;
		/* new section start or end point are within range */
		if (newrange->start <= rstart && newrange->end >= rstart)
			fail = -1;
		if (newrange->start <= rend && newrange->end >= rend)
			fail = -1;
		if (fail) {
			printf("Error: overlapping IO regions: %s and %s\n",
				newrange->name, name);
			return -1;
		}
		newrange = newrange->next;
	}

	newrange = malloc(sizeof(iorange_t));

	newrange->name = name;
	newrange->ops = ops;
	newrange->start = rstart;
	newrange->end = rend;
	newrange->next = ioranges;

	ioranges = newrange;

	return 0;
}

int is_loaded(const char *plugin_name)
{
	plugin_t *p = plugins;
	while (p) {
		if (!strcmp(plugin_name, p->name))
			return -1;
		p = p->next;
	}
	return 0;
}

int load_plugin(const char *plugin_name)
{
	void *handle;
	char *error;
	char path[PATHSIZE];

	int (*init_plugin) (void);
	char **deps;
	char **plugin_info;
	plugin_t *p;

	if (is_loaded(plugin_name)) {
		printf("Plugin %s already loaded.\n", plugin_name);
		return 0;
	}

	strncpy(path, PLUGINDIR, PATHSIZE);
	strncat(path, "/plugin_", PATHSIZE);
	strncat(path, plugin_name, PATHSIZE);
	strncat(path, ".so", PATHSIZE);

#if DEBUG
	printf("Opening plugin %s\n", path);
#endif

	handle = dlopen(path, RTLD_LAZY | RTLD_GLOBAL);
	if (!handle) {
		error = dlerror();
		printf("Error: Could not open plugin \"%s\": %s\n",
		       plugin_name, error);
		exit(1);
	}
#ifdef CONFIG_DEBUG_PLUGINS
	plugin_info = dlsym(handle, "plugin_author");
	if ((error = dlerror()) == NULL)
		printf("Plugin %s author:  %s\n", plugin_name, *plugin_info);
	plugin_info = dlsym(handle, "plugin_license");
	if ((error = dlerror()) == NULL)
		printf("Plugin %s license: %s\n", plugin_name, *plugin_info);
	plugin_info = dlsym(handle, "plugin_description");
	if ((error = dlerror()) == NULL)
		printf("Plugin %s descr.: %s\n", plugin_name, *plugin_info);
#endif
	p = malloc(sizeof(plugin_t));
	p->next = plugins;
	p->name = plugin_name;
	plugins = p;

	deps = dlsym(handle, "plugin_deps");
	if ((error = dlerror()) != NULL)
		deps = NULL;


	strncpy(path, "plugin_", PATHSIZE);
	strncat(path, plugin_name, PATHSIZE);
	strncat(path, "_init", PATHSIZE);

	init_plugin = dlsym(handle, path);
	if ((error = dlerror()) != NULL) {
		printf("error: %s\n", error);
		exit(1);
	}

	if (deps) {
		int i = 0;
		char *walk = deps[0];
#ifdef CONFIG_DEBUG_PLUGINS
		printf("\nPlugin %s dependencies:", plugin_name);
#endif
		while (walk) {
			printf(" %s", walk);
			if (!is_loaded(walk)) {
#ifdef CONFIG_DEBUG_PLUGINS
				printf("(loading)\n");
#endif
				load_plugin(walk);
			}
#ifdef CONFIG_DEBUG_PLUGINS
			else {
				printf("(loaded)");
			}
#endif
			walk = deps[++i];
		}
	}

	printf("\n");
#if DEBUG
	printf("Initializing module:\n");
#endif

	return init_plugin();

	// We don't dlclose the handle here since
	// we want to keep our symbols for later use.
}
