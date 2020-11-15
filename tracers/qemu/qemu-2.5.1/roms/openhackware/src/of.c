/* Open firmware emulation.
 *
 * This is really simplistic. The first goal is to implement all stuff
 * needed to boot Linux. Then, I'll try Darwin.
 * Note that this emulation run in the host environment.
 * There is no Forth interpreter, so standard bootloader cannot be launched.
 * In the future, it will be nice to get a complete OpenFirmware implementation
 * so that OSes can be launched exactly the way they are in the real world...
 *
 *  Copyright (c) 2003-2005 Jocelyn Mayer
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

#include <stdlib.h>
#include <stdio.h>
#include "bios.h"

//#define DEBUG_OF 1

#if defined (DEBUG_OF)
#define OF_DPRINTF(fmt, args...) \
do { dprintf("%s: " fmt, __func__ , ##args); } while (0)
#else
#define OF_DPRINTF(fmt, args...) \
do { } while (0)
#endif

#define PROT_READ  1
#define PROT_WRITE 2

typedef struct OF_transl_t OF_transl_t;
struct OF_transl_t {
    uint32_t virt;
    uint32_t size;
    uint32_t phys;
    uint32_t mode;
};

typedef struct OF_env_t OF_env_t;
struct OF_env_t {
    uint32_t *stackp; /* Stack pointer          */
    uint32_t *stackb; /* Stack base             */
    uint32_t *funcp;  /* Function stack pointer */
    uint32_t *funcb;  /* Function stack base    */
};

typedef struct OF_bustyp_t OF_bustyp_t;
struct OF_bustyp_t {
    const char *name;
    int type;
};

typedef struct pci_address_t pci_address_t;
struct pci_address_t {
	uint32_t hi;
	uint32_t mid;
	uint32_t lo;
};

typedef struct pci_reg_prop_t pci_reg_prop_t;
struct pci_reg_prop_t {
	pci_address_t addr;
	uint32_t size_hi;
	uint32_t size_lo;
};

typedef struct pci_range_t pci_range_t;
struct pci_range_t {
	pci_address_t addr;
	uint32_t phys;
	uint32_t size_hi;
	uint32_t size_lo;
};

/*****************************************************************************/
__attribute__ (( section (".OpenFirmware") ))
static void OF_lds (uint8_t *dst, const void *address)
{
    const uint8_t *p;
    uint8_t *_d = dst;

    for (p = address; *p != '\0'; p++) {
        *_d++ = *p;
    }
    *_d = '\0';
    OF_DPRINTF("Loaded string %s\n", dst); 
}

__attribute__ (( section (".OpenFirmware") ))
static void OF_sts (void *address, const uint8_t *src)
{
    const uint8_t *_s;
    uint8_t *p = address;

    OF_DPRINTF("Store string %s\n", src);
    for (_s = src; *_s != '\0'; _s++) {
        *p++ = *_s;
    }
    *p = '\0';
}

#define OF_DUMP_STRING(env, buffer)    \
do {                                   \
    unsigned char tmp[OF_NAMELEN_MAX]; \
    OF_lds(tmp, buffer);               \
    OF_DPRINTF("[%s]\n", tmp);         \
} while (0)

/*****************************************************************************/
/* Forth like environmnent */
#define OF_CHECK_NBARGS(env, nb)                                              \
do {                                                                          \
    int nb_args;                                                              \
    nb_args = stackd_depth((env));                                            \
    if (nb_args != (nb)) {                                                    \
        printf("%s: Bad number of arguments (%d - %d)\n",                     \
               __func__, nb_args, (nb));                                      \
        bug();                                                                \
        popd_all((env), nb_args);                                             \
        pushd((env), -1);                                                     \
        return;                                                               \
    }                                                                         \
} while (0)

#define OF_STACK_SIZE 0x1000
#define OF_FSTACK_SIZE 0x100
__attribute__ (( section (".OpenFirmware_vars") ))
uint8_t OF_stack[OF_STACK_SIZE];
__attribute__ (( section (".OpenFirmware_vars") ))
uint8_t OF_fstack[OF_FSTACK_SIZE];

typedef void (*OF_cb_t)(OF_env_t *OF_env);

static inline void _push (uint32_t **stackp, uint32_t data)
{
    //    OF_DPRINTF("%p 0x%0x\n", *stackp, data);
    **stackp = data;
    (*stackp)--;
}

static inline uint32_t _pop (uint32_t **stackp)
{
    (*stackp)++;
    //    OF_DPRINTF("%p 0x%0x\n", *stackp, **stackp);
    return **stackp;
}

static inline void _pop_all (uint32_t **stackp, int nb)
{
    int i;

    for (i = 0; i < nb; i++)
        (*stackp)++;
}

static inline int _stack_depth (uint32_t *stackp, uint32_t *basep)
{
    return basep - stackp;
}

static inline void pushd (OF_env_t *OF_env, uint32_t data)
{
    _push(&OF_env->stackp, data);
}

static inline uint32_t popd (OF_env_t *OF_env)
{
    return _pop(&OF_env->stackp);
}

static inline void popd_all (OF_env_t *OF_env, int nb)
{
    _pop_all(&OF_env->stackp, nb);
}

static inline int stackd_depth (OF_env_t *OF_env)
{
    return _stack_depth(OF_env->stackp, OF_env->stackb);
}

static inline void pushf (OF_env_t *OF_env, OF_cb_t *func)
{
    _push(&OF_env->funcp, (uint32_t)func);
}

static inline OF_cb_t *popf (OF_env_t *OF_env)
{
    return (OF_cb_t *)_pop(&OF_env->funcp);
}

static inline void popf_all (OF_env_t *OF_env, int nb)
{
    _pop_all(&OF_env->funcp, nb);
}

static inline int stackf_depth (OF_env_t *OF_env)
{
    return _stack_depth(OF_env->funcp, OF_env->funcb);
}

static inline void OF_env_init (OF_env_t *OF_env)
{
    OF_env->stackb = (uint32_t *)(OF_stack + OF_STACK_SIZE - 4);
    OF_env->stackp = OF_env->stackb;
    OF_env->funcb = (uint32_t *)(OF_fstack + OF_FSTACK_SIZE - 4);
    OF_env->funcp = OF_env->funcb;
}

/* Forth run-time */
__attribute__ (( section (".OpenFirmware") ))
static void C_to_Forth (OF_env_t *env, void *p, OF_cb_t *cb)
{
    OF_cb_t *_cb;
    uint32_t *u, *rets;
    uint32_t i, n_args, n_rets, tmp;

    //    OF_DPRINTF("enter\n");
    /* Fill argument structure */
    u = p;
    n_args = *u++;
    n_rets = *u++;
    u += n_args;
    rets = u;
    //    OF_DPRINTF("n_args=%d n_rets=%d\n", n_args, n_rets);
    /* Load arguments */
    for (i = 0; i < n_args; i++)
        pushd(env, *(--u));
    pushf(env, cb);
    while (stackf_depth(env) != 0) {
        //        OF_DPRINTF("func stack: %p %p\n", env->funcb, env->funcp);
        _cb = popf(env);
        //        OF_DPRINTF("Next func: %p %d\n", cb, stackf_depth(env));
        (*_cb)(env);
    }
    //    OF_DPRINTF("Back to C: n_args=%d n_rets=%d\n", n_args, n_rets);
    /* Copy returned values */
    for (i = 0; stackd_depth(env) != 0; i++) {
        tmp = popd(env);
        //        OF_DPRINTF("Store 0x%0x (%d)\n", tmp, tmp);
        *rets++ = tmp;
    }
    for (; i < n_rets; i++)
        *rets++ = 0;
    OF_CHECK_NBARGS(env, 0);
    //    OF_DPRINTF("done\n");
}

/*****************************************************************************/
/* Memory pool (will be needed when it'll become native) */
#if 0
#define OF_INTBITS_LEN 128
#define OF_INTPOOL_LEN (OF_INTBITS_LEN * 8)
__attribute__ (( section (".OpenFirmware_vars") ))
static uint32_t OF_int_pool[OF_INTPOOL_LEN];
__attribute__ (( section (".OpenFirmware_vars") ))
static uint8_t  OF_int_bits[OF_INTBITS_LEN];

__attribute__ (( section (".OpenFirmware") ))
static uint32_t *OF_int_alloc (unused OF_env_t *env)
{
    uint8_t tmp;
    int i, j;

    for (i = 0; i < OF_INTBITS_LEN; i++) {
        tmp = OF_int_bits[i];
        if (tmp == 0xFF)
            continue;
        for (j = 0; j < 7; j++) {
            if ((tmp & 1) == 0) {
                OF_int_bits[i] |= 1 << j;
                return &OF_int_pool[(i << 3) | j];
            }
            tmp = tmp >> 1;
        }
    }
    printf("ALERT: unable to \"allocate\" new integer\n");
    
    return NULL;
}

__attribute__ (( section (".OpenFirmware") ))
static void OF_int_free (unused OF_env_t *env,
                         uint32_t *area)
{
    int i, j;

    i = area - OF_int_pool;
    j = i & 7;
    i = i >> 3;
    OF_int_bits[i] &= ~(1 << j);
}

__attribute__ (( section (".OpenFirmware") ))
static void OF_free (unused OF_env_t *env, void *area)
{
    uint32_t *check;

    /* Check if it's in our int pool */
    check = area;
    if (check >= OF_int_pool && check < (OF_int_pool + OF_INTPOOL_LEN)) {
        OF_int_free(env, check);
        return;
    }
#if 0
    free(area);
#endif
}
#endif

/*****************************************************************************/
/*                          Internal structures                              */
/* Property value types */
typedef struct OF_node_t OF_node_t;
typedef struct OF_prop_t OF_prop_t;
typedef struct OF_method_t OF_method_t;
typedef struct OF_inst_t OF_inst_t;

#define OF_ADDRESS_NONE ((uint32_t)(-1))

/* Tree node */
struct OF_node_t {
    /* Parent node */
    OF_node_t *parent;
    /* Link to next node at the same level */
    OF_node_t *next;
    /* Link to children, if any */
    OF_node_t *children, *child_last;
    /* refcount */
    int refcount;
    /* The following ones belong to the package */
    /* Package */
    uint16_t pack_id;
    /* links count */
    uint16_t link_count;
    uint16_t link_cur;
    OF_node_t *link_ref;
    /* Properties */
    OF_prop_t *properties, *prop_last, *prop_name, *prop_address;
    /* Methods */
    OF_method_t *methods, *method_last;
    /* private data */
    void *private_data;
    /* static data */
    void *static_data;
    /* instances */
    OF_inst_t *instances, *inst_last;
};

/* Node property */
struct OF_prop_t {
    /* Link to next property */
    OF_prop_t *next;
    /* The node it belongs to */
    OF_node_t *node;
    /* property name */
    const unsigned char *name;
    /* property value len */
    int vlen;
    /* property value buffer */
    char *value;
    /* Property change callback */
    void (*cb)(OF_env_t *OF_env, OF_prop_t *prop, const void *data, int len);
};

/* Node method */
enum {
    OF_METHOD_INTERNAL = 0,
    OF_METHOD_EXPORTED,
};

struct OF_method_t {
    /* Link to next method */
    OF_method_t *next;
    /* The package it belongs to */
    OF_node_t *node;
    /* method name */
    unsigned char *name;
    /* Method function pointer */
    OF_cb_t func;
};

/* Package instance */
struct OF_inst_t {
    /* Link to next instance of the same package */
    OF_inst_t *next;
    /* Link to the parent instance */
    OF_inst_t *parent;
    /* The package it belongs to */
    OF_node_t *node;
    /* Instance identifier */
    uint16_t inst_id;
    /* Instance data */
    void *data;
};

/* reg property */
typedef struct OF_regprop_t OF_regprop_t;
struct OF_regprop_t {
    uint32_t address;
    uint32_t size;
};

/* range property */
typedef struct OF_range_t OF_range_t;
struct OF_range_t {
    uint32_t virt;
    uint32_t size;
    uint32_t phys;
};

/* Open firmware tree */
#define OF_MAX_PACKAGE 256
/* nodes and packages */
__attribute__ (( section (".OpenFirmware_vars") ))
static OF_node_t *OF_node_root;
__attribute__ (( section (".OpenFirmware_vars") ))
static uint16_t OF_pack_last_id = 0;
__attribute__ (( section (".OpenFirmware_vars") ))
static uint16_t inst_last_id = 0;
/* To speed up lookup by id, we get a package table */
__attribute__ (( section (".OpenFirmware_vars") ))
static OF_node_t *OF_packages[OF_MAX_PACKAGE];
__attribute__ (( section (".OpenFirmware_vars") ))
static OF_node_t *OF_pack_active;

static OF_prop_t *OF_prop_string_new (OF_env_t *env, OF_node_t *node,
                                      const unsigned char *name,
                                      const unsigned char *string);
static OF_prop_t *OF_prop_int_new (OF_env_t *env, OF_node_t *node,
                                   const unsigned char *name, uint32_t value);
static OF_prop_t *OF_property_get (OF_env_t *env, OF_node_t *node,
                                   const unsigned char *name);
static uint16_t OF_pack_handle (OF_env_t *env, OF_node_t *node);

__attribute__ (( section (".OpenFirmware_vars") ))
static uint8_t *RTAS_memory;

/*****************************************************************************/
/*                           Node management                                 */
/* Insert a new node */
__attribute__ (( section (".OpenFirmware") ))
static uint16_t OF_pack_new_id (unused OF_env_t *env, OF_node_t *node)
{
    uint16_t cur_id;

    for (cur_id = OF_pack_last_id + 1; cur_id != OF_pack_last_id; cur_id++) {
        if (cur_id == (uint16_t)(OF_MAX_PACKAGE))
            cur_id = 1;
        if (OF_packages[cur_id] == NULL) {
            OF_packages[cur_id] = node;
            OF_pack_last_id = cur_id;
            return cur_id;
        }
    }

    return (uint16_t)(-1);
}

static OF_node_t *OF_node_create (OF_env_t *env, OF_node_t *parent,
                                  const unsigned char *name, uint32_t address)
{
    OF_node_t *new;

    OF_DPRINTF("New node: %s\n", name);
    new = malloc(sizeof(OF_node_t));
    if (new == NULL) {
        ERROR("%s can't alloc new node '%s'\n", __func__, name);
        return NULL;
    }
    memset(new, 0, sizeof(OF_node_t));
    new->parent = parent;
    new->refcount = 1;
    new->link_count = 1;
    new->prop_name = OF_prop_string_new(env, new, "name", name);
    if (new->prop_name == NULL) {
        free(new);
        ERROR("%s can't alloc new node '%s' name\n", __func__, name);
        return NULL;
    }
    new->prop_address = OF_prop_int_new(env, new, "unit-address", address);
    if (new->prop_address == NULL) {
        free(new->prop_name->value);
        free(new->prop_name);
        free(new);
        ERROR("%s can't alloc new node '%s' address\n", __func__, name);
        return NULL;
    }
    /* Link it in parent tree */
    if (parent != NULL) {
        /* SHOULD LOCK */
        if (parent->children == NULL) {
            parent->children = new;
        } else {
            parent->child_last->next = new;
        }
        parent->child_last = new;
    } else {
        /* This is a bug and should never happen, but for root node */
        if (strcmp(name, "device-tree") != 0)
            ERROR("WARNING: parent of '%s' is NULL!\n", name);
    }
    //    OF_DPRINTF("New node: %s get id\n", name);

    return new;
}

__attribute__ (( section (".OpenFirmware") ))
static OF_node_t *OF_node_new (OF_env_t *env, OF_node_t *parent,
                               const unsigned char *name, uint32_t address)
{
    OF_node_t *new;

    new = OF_node_create(env, parent, name, address);
    if (new == NULL)
        return NULL;
    new->pack_id = OF_pack_new_id(env, new);
    //    OF_DPRINTF("New node: %s id=0x%0x\n", name, new->pack_id);
    OF_pack_active = new;

    return new;
}

static inline OF_node_t *OF_node_parent (unused OF_env_t *env, OF_node_t *node)
{
    return node->parent;
}

/* Look for a node, given its name */
__attribute__ (( section (".OpenFirmware") ))
static OF_node_t *OF_node_get_child (OF_env_t *env, OF_node_t *parent,
                                     const unsigned char *name,
                                     uint32_t address)
{
    unsigned char tname[OF_NAMELEN_MAX];
    OF_node_t *parse, *tmp;
    OF_prop_t *prop_name, *prop_address;
    uint32_t *addr_valp;
    int len, i;

    if (parent == OF_node_root) {
       OF_DPRINTF("Look for node [%s]\n", name);
    }
    len = strlen(name);
    memcpy(tname, name, len + 1);
    for (i = len; i > 0; i--) {
        if (tname[i - 1] == ',') {
            tname[i - 1] = '\0';
            len = i;
            break;
        }
    }
    for (parse = parent->children; parse != NULL; parse = parse->next) {
        prop_name = parse->prop_name;
        prop_address = parse->prop_address;
        if (prop_address == NULL)
            addr_valp = NULL;
        else
            addr_valp = (void *)prop_address->value;
#if 0
        OF_DPRINTF("node [%s] <=> [%s]\n", prop_name->value, tname);
#endif
        if (prop_name != NULL && strncmp(prop_name->value, tname, len) == 0 &&
            (prop_name->value[len] == '\0') &&
            (address == OF_ADDRESS_NONE || addr_valp == NULL ||
             address == *addr_valp)) {
            parse->refcount++;
            return parse;
        }
#if 1
        OF_DPRINTF("look in children [%s]\n", prop_name->value);
#endif
        tmp = OF_node_get_child(env, parse, tname, address);
        if (tmp != NULL)
            return tmp;
#if 0
        OF_DPRINTF("didn't find in children [%s]\n", prop_name->value);
#endif
    }
    if (parent == OF_node_root) {
        OF_DPRINTF("node [%s] not found\n", name);
    }

    return NULL;
}

__attribute__ (( section (".OpenFirmware") ))
static OF_node_t *OF_node_get (OF_env_t *env, const unsigned char *name)
{
    unsigned char tname[OF_NAMELEN_MAX];
    unsigned char *addrp;
    uint32_t address;

    if (strcmp(name, "device_tree") == 0)
        return OF_node_root;

    strcpy(tname, name);
    addrp = strchr(tname, '@');
    if (addrp == NULL) {
        address = OF_ADDRESS_NONE;
    } else {
        *addrp++ = '\0';
        address = strtol(addrp, NULL, 16);
    }

    /* SHOULD LOCK */
    return OF_node_get_child(env, OF_node_root, name, address);
}

/* Release a node */
__attribute__ (( section (".OpenFirmware") ))
static void OF_node_put (unused OF_env_t *env, OF_node_t *node)
{
    if (--node->refcount < 0)
        node->refcount = 0;
}

/*****************************************************************************/
/*                           Packages tree walk                              */
__attribute__ (( section (".OpenFirmware") ))
static uint16_t OF_pack_handle (unused OF_env_t *env, OF_node_t *node)
{
    if (node == NULL)
        return 0;

    return node->pack_id;
}

__attribute__ (( section (".OpenFirmware") ))
static OF_node_t *OF_pack_find_by_name (OF_env_t *env, OF_node_t *base,
                                        const unsigned char *name)
{
    unsigned char tmp[OF_NAMELEN_MAX], *addrp;
    const unsigned char *sl, *st;
    OF_node_t *parse;
    OF_prop_t *prop_name, *prop_address;
    uint32_t address, *addr_valp;
    int len;

    OF_DPRINTF("Path [%s] in '%s'\n", name, base->prop_name->value);
    st = name;
    if (*st == '/') {
        st++;
    }
    if (*st == '\0') {
        /* Should never happen */
        OF_DPRINTF("Done\n");
        return base;
    }
    sl = strchr(st, '/');
    if (sl == NULL) {
        len = strlen(st);
    } else {
        len = sl - st;
    }
    memcpy(tmp, st, len);
    tmp[len] = '\0';
    addrp = strchr(tmp, '@');
    if (addrp == NULL) {
        address = OF_ADDRESS_NONE;
    } else {
        len = addrp - tmp;
        *addrp++ = '\0';
        address = strtol(addrp, NULL, 16);
    }
    OF_DPRINTF("Look for [%s] '%s' %08x\n", tmp, sl, address);
    for (parse = base->children; parse != NULL; parse = parse->next) {
        prop_name = parse->prop_name;
        prop_address = parse->prop_address;
        if (prop_address == NULL)
            addr_valp = NULL;
        else
            addr_valp = (void *)prop_address->value;
#if 0
        OF_DPRINTF("Check [%s]\n", prop_name->value);
#endif
        if (prop_name == NULL) {
            printf("ERROR: missing address in node, parent: '%s'\n",
                   base->prop_name->value);
            bug();
        }
        if (strncmp(prop_name->value, tmp, len) == 0 &&
            prop_name->value[len] == '\0' &&
            (address == OF_ADDRESS_NONE || addr_valp == NULL ||
             address == *addr_valp)) {
            OF_pack_active = parse;
            if (sl == NULL) {
                OF_DPRINTF("Done\n");
                return parse;
            }
            OF_DPRINTF("Recurse: '%s'\n", sl + 1);
            return OF_pack_find_by_name(env, parse, sl + 1);
        }
    }
    OF_DPRINTF("Didn't found [%s]\n", tmp);

    return NULL;
}

__attribute__ (( section (".OpenFirmware") ))
static OF_node_t *OF_pack_find (unused OF_env_t *env, uint16_t phandle)
{
    if (phandle > OF_MAX_PACKAGE)
        return NULL;
    if (OF_packages[phandle] == NULL) {
        OF_DPRINTF("No package %0x\n", phandle);
    } else {
        OF_DPRINTF("return package: %0x %p [%s]\n", phandle,
                   OF_packages[phandle],
                   OF_packages[phandle]->prop_name->value);
    }

    return OF_packages[phandle];
}

__attribute__ (( section (".OpenFirmware") ))
static OF_node_t *OF_pack_next (OF_env_t *env, uint16_t phandle)
{
    OF_node_t *node;

    for (node = OF_pack_find(env, phandle); node != NULL; node = node->next) {
        if (OF_pack_handle(env, node) != phandle)
            break;
    }
#if 0
    OF_DPRINTF("found node %p [%s]\n", node, node->prop_name->value);
#endif

    return node;
}

__attribute__ (( section (".OpenFirmware") ))
static OF_node_t *OF_pack_child (OF_env_t *env, uint16_t phandle)
{
    OF_node_t *node;

    node = OF_pack_find(env, phandle);
    if (node == NULL) {
        ERROR("%s didn't find pack %04x\n", __func__, phandle);
        return NULL;
    }
    node = node->children;
#if 0
    OF_DPRINTF("found node %p [%s]\n", node, node->prop_name->value);
#endif

    return node;
}

__attribute__ (( section (".OpenFirmware") ))
static OF_node_t *OF_pack_parent (OF_env_t *env, uint16_t phandle)
{
    OF_node_t *node;

    node = OF_pack_find(env, phandle);
    if (node == NULL) {
        ERROR("%s didn't find pack %04x\n", __func__, phandle);
        return NULL;
    }
    node = OF_node_parent(env, node);
#if 0
    OF_DPRINTF("found node %p [%s]\n", node, node->prop_name->value);
#endif

    return node;
}

/*****************************************************************************/
/*                      Package properties management                        */
/* Insert a new property */
__attribute__ (( section (".OpenFirmware") ))
static OF_prop_t *OF_property_new (unused OF_env_t *env, OF_node_t *node,
                                   const unsigned char *name,
                                   const void *data, int len)
{
    OF_prop_t *prop;

#ifdef DEBUG_OF
    {
        OF_prop_t *_prop;
        _prop = OF_property_get(env, node, name);
        if (_prop != NULL) {
            printf("Property '%s' already present !\n", name);
            bug();
        }
    }
#endif
    /* Allocate a new property */
    prop = malloc(sizeof(OF_prop_t));
    if (prop == NULL) {
        ERROR("%s cannot allocate property '%s'\n", __func__, name);
        return NULL;
    }
    memset(prop, 0, sizeof(OF_prop_t));
    prop->name = strdup(name);
    if (prop->name == NULL) {
        free(prop);
        ERROR("%s cannot allocate property '%s' name\n", __func__, name);
        return NULL;
    }
    /* Fill it */
    if (data != NULL && len > 0) {
        prop->value = malloc(len);
        if (prop->value == NULL) {
            free(prop);
            ERROR("%s cannot allocate property '%s' value\n", __func__, name);
            return NULL;
        }
        prop->vlen = len;
        memcpy(prop->value, data, len);
    }
    OF_DPRINTF("New property [%s] '%s'\n\t%p %p %d %p\n", name, prop->name, prop->name, data, len, prop->value);
    /* Link it */
    /* SHOULD LOCK */
    if (node->properties == NULL)
        node->properties = prop;
    else
        node->prop_last->next = prop;
    node->prop_last = prop;
    
    return prop;
}

/* Find a property given its name */
__attribute__ (( section (".OpenFirmware") ))
static OF_prop_t *OF_property_get (unused OF_env_t *env, OF_node_t *node,
                                   const unsigned char *name)
{
    OF_prop_t *prop;
    
#if 0
    OF_DPRINTF("Look for property [%s] in 0x%0x '%s'\n", name,
               node->pack_id, node->prop_name->value);
#endif
    if (node == NULL)
        return NULL;
    /* *SHOULD LOCK* */
    for (prop = node->properties; prop != NULL; prop = prop->next) {
#if 0
        OF_DPRINTF("property [%s] <=> [%s]\n", prop->name, name);
#endif
        if (strcmp(prop->name, name) == 0) {
            return prop;
        }
    }
#if 0
    OF_DPRINTF("property [%s] not found in 0x%08x '%s'\n", name,
               node->pack_id, node->prop_name->value);
#endif

    return NULL;
}

/* Change a property */
__attribute__ (( section (".OpenFirmware") ))
static OF_prop_t *OF_property_set (OF_env_t *env, OF_node_t *node,
                                   const unsigned char *name,
                                   const void *data, int len)
{
    OF_prop_t *prop;
    void *tmp;

    if (node == NULL)
        return NULL;
    prop = OF_property_get(env, node, name);
    if (prop != NULL) {
        OF_DPRINTF("change property [%s]\n", name);
        tmp = malloc(len);
        if (tmp == NULL && len != 0) {
            ERROR("%s cannot set property '%s'\n", __func__, name);
            return NULL;
        }
        free(prop->value);
        prop->value = tmp;
        prop->vlen = len;
        memcpy(prop->value, data, len);
        if (prop->cb != NULL) {
            (*prop->cb)(env, prop, data, len);
        }
    } else {
        OF_DPRINTF("new property [%s]\n", name);
        prop = OF_property_new(env, node, name, data, len);
    }

    return prop;
}

__attribute__ (( section (".OpenFirmware") ))
static int OF_property_len (OF_env_t *env, OF_node_t *node,
                            const unsigned char *name)
{
    OF_prop_t *prop;

    prop = OF_property_get(env, node, name);
    if (prop == NULL)
        return -1;
    
    return prop->vlen;
}

__attribute__ (( section (".OpenFirmware") ))
static unsigned char *hex2buf (unsigned char *buf, uint32_t value, int fill)
{
    int pos, d;
    
    buf[8] = '\0';
    pos = 7;
    if (value == 0) {
        buf[pos--] = '0';
    } else {
        for (; value != 0; pos--) {
            d = value & 0xF;
            if (d > 9)
            d += 'a' - '0' - 10;
            buf[pos] = d + '0';
            value = value >> 4;
        }
    }
    if (fill != 0) {
        for (; pos != -1; pos--) {
            buf[pos] = '0';
        }
    }

    return &buf[pos];
}

__attribute__ (( section (".OpenFirmware") ))
static int OF_property_copy (OF_env_t *env, void *buffer, int maxlen,
                             OF_node_t *node, const unsigned char *name)
{
    unsigned char tmp[OF_PROPLEN_MAX];
    OF_prop_t *prop;
    int len;

    prop = OF_property_get(env, node, name);
    if (prop == NULL) {
        ERROR("%s cannot get property '%s' for %s\n", __func__, name,
              node->prop_name->value);
        return -1;
    }
    len = prop->vlen > maxlen ? maxlen : prop->vlen;
    if (prop->value != NULL) {
        tmp[0] = '0';
        tmp[1] = 'x';
        hex2buf(tmp + 2, *((uint32_t *)prop->value), 1);
    } else {
        *tmp = '\0';
    }
    OF_DPRINTF("copy property [%s] len=%d to %p len=%d\n",
               name, prop->vlen, buffer, maxlen);
    if (strcmp(name, "name") == 0) {
        OF_DPRINTF("=> '%s'\n", prop->value);
    }
    memcpy(buffer, prop->value, len);
    //    OF_DPRINTF("done\n");

    return len;
}

__attribute__ (( section (".OpenFirmware") ))
static OF_prop_t *OF_property_next (OF_env_t *env, OF_node_t *node,
                                    const unsigned char *name)
{
    OF_prop_t *prop, *next;

    if (name == NULL || *name == '\0') {
        next = node->properties;
    } else {
        prop = OF_property_get(env, node, name);
        if (prop == NULL) {
            OF_DPRINTF("Property [%s] not found\n", name);
            next = NULL;
        } else {
            next = prop->next;
            /* Skip address if not set */
            if (next == node->prop_address &&
                *((uint32_t *)next->value) == OF_ADDRESS_NONE)
                next = next->next;
        }
    }
#if 0
    OF_DPRINTF("Found property %p\n", next);
#endif

    return next;
}

/* Simplified helpers */
__attribute__ (( section (".OpenFirmware") ))
static OF_prop_t *OF_prop_string_new (OF_env_t *env, OF_node_t *node,
                                      const unsigned char *name,
                                      const unsigned char *string)
{
#ifdef DEBUG_OF
    {
        OF_prop_t *prop;
        prop = OF_property_get(env, node, name);
        if (prop != NULL) {
            printf("Property '%s' already present !\n", name);
            bug();
        }
    }
#endif
    return OF_property_new(env, node, name,
                           string, strlen(string) + 1);
}

/* convert '\1' char to '\0' */
static OF_prop_t *OF_prop_string_new1 (OF_env_t *env, OF_node_t *node,
                                       const unsigned char *name,
                                       const unsigned char *string)
{
    int len, i;
    OF_prop_t *ret;
    unsigned char *str;

    if (strchr(string, '\1') == NULL) {
        return OF_prop_string_new(env, node, name, string);
    } else {
        len = strlen(string) + 1;
        str = malloc(len);
        if (!str)
            return NULL;
        memcpy(str, string, len);
        for(i = 0; i < len; i++)
            if (str[i] == '\1')
                str[i] = '\0';
        ret = OF_property_new(env, node, name,
                              str, len);
        free(str);
        return ret;
    }
}

__attribute__ (( section (".OpenFirmware") ))
static OF_prop_t *OF_prop_int_new (OF_env_t *env, OF_node_t *node,
                                   const unsigned char *name, uint32_t value)
{
#ifdef DEBUG_OF
    {
        OF_prop_t *prop;
        prop = OF_property_get(env, node, name);
        if (prop != NULL) {
            printf("Property '%s' already present !\n", name);
            bug();
        }
    }
#endif
    return OF_property_new(env, node, name, &value, sizeof(uint32_t));
}

__attribute__ (( section (".OpenFirmware") ))
static OF_prop_t *OF_prop_string_set (OF_env_t *env, OF_node_t *node,
                                      const unsigned char *name,
                                      const unsigned char *string)
{
    const unsigned char *tmp;

    tmp = strdup(string);
    if (tmp == NULL) {
        ERROR("%s cannot duplicate property '%s'\n", __func__, name);
        return NULL;
    }

    return OF_property_set(env, node, name, tmp, strlen(string) + 1);
}

__attribute__ (( section (".OpenFirmware") ))
static OF_prop_t *OF_prop_int_set (OF_env_t *env, OF_node_t *node,
                                   const unsigned char *name, uint32_t value)
{
    return OF_property_set(env, node, name, &value, sizeof(uint32_t));
}

__attribute__ (( section (".OpenFirmware") ))
unused
static OF_prop_t *OF_set_compatibility (OF_env_t *env, OF_node_t *node,
                                        const unsigned char *compat)
{
    return OF_prop_string_new(env, node, "compatible", compat);
}

__attribute__ (( section (".OpenFirmware") ))
static inline void OF_property_set_cb (unused OF_env_t *OF_env,
                                       OF_prop_t *prop,
                                       void (*cb)(OF_env_t *OF_env,
                                                  OF_prop_t *prop,
                                                  const void *data, int len))
{
    prop->cb = cb;
}

/*****************************************************************************/
/*                       Packages methods management                         */
__attribute__ (( section (".OpenFirmware") ))
static OF_method_t *OF_method_new (unused OF_env_t *env, OF_node_t *node,
                                   const unsigned char *name, OF_cb_t cb)
{
    OF_method_t *new;

    new = malloc(sizeof(OF_method_t));
    if (new == NULL) {
        ERROR("%s cannot allocate method '%s'\n", __func__, name);
        return NULL;
    }
    memset(new, 0, sizeof(OF_method_t));
    new->node = node;
    new->name = strdup(name);
    if (new->name == NULL) {
        free(new);
        ERROR("%s cannot allocate method '%s' name\n", __func__, name);
        return NULL;
    }
    OF_DPRINTF("new method name %p %s\n", new, new->name);
    new->func = cb;
    /* Link it */
    /* *SHOULD LOCK* */
    if (node->method_last == NULL)
        node->methods = new;
    else
        node->method_last->next = new;
    node->method_last = new;

    return new;
}

__attribute__ (( section (".OpenFirmware") ))
static OF_method_t *OF_method_get (unused OF_env_t *env, OF_node_t *node,
                                   const unsigned char *name)
{
    OF_method_t *parse;

    if (node == NULL) {
        OF_DPRINTF("No method in NULL package !\n");
        return NULL;
    }
#if 0
    OF_DPRINTF("Look for method %s in package %0x\n",
               name, node->pack_id);
#endif
    for (parse = node->methods; parse != NULL; parse = parse->next) {
#if 0
        OF_DPRINTF("check %p %p\n", parse, parse->name);
        OF_DPRINTF("name=%s\n", parse->name);
#endif
        if (strcmp(parse->name, name) == 0)
            return parse;
    }

    return NULL;
}

/*****************************************************************************/
/*                     Packages instances management                         */
__attribute__ (( section (".OpenFirmware") ))
static uint16_t OF_inst_new_id (unused OF_env_t *env, OF_node_t *node)
{
    OF_inst_t *tmp_inst;
    uint16_t cur_id;

#if 0
    OF_DPRINTF("[%s] %d\n", node->prop_name->value,
               inst_last_id);
#endif
    for (cur_id = inst_last_id + 1;
         cur_id != inst_last_id; cur_id++) {
        if (cur_id == (uint16_t)(OF_MAX_PACKAGE))
            cur_id = 0;
        for (tmp_inst = node->instances; tmp_inst != NULL;
             tmp_inst = tmp_inst->next) {
            if (tmp_inst->inst_id == cur_id)
                continue;
        }
        inst_last_id = cur_id;
#if 1
        OF_DPRINTF("0x%0x\n", cur_id);
#endif
        return cur_id;
    }
    OF_DPRINTF("no ID found\n");

    return (uint16_t)(-1);
}

/* Create a new package's instance */
__attribute__ (( section (".OpenFirmware") ))
static OF_inst_t *OF_instance_new (OF_env_t *env, OF_node_t *node)
{
    OF_inst_t *new, *parent;
    uint16_t new_id;

    /* TODO: recurse to root... */
    new = malloc(sizeof(OF_inst_t));
    if (new == NULL) {
        ERROR("%s cannot allocate instance of '%s'\n", __func__,
              node->prop_name->value);
        return NULL;
    }
    memset(new, 0, sizeof(OF_inst_t));
    if (OF_node_parent(env, node) != NULL) {
        parent = OF_instance_new(env, OF_node_parent(env, node));
        if (parent == NULL) {
            free(new);
            ERROR("%s cannot allocate instance of '%s' parent\n", __func__,
                  node->prop_name->value);
            return NULL;
        }
        new->parent = parent;
    } else {
        new->parent = NULL;
    }
    new_id = OF_inst_new_id(env, node);
    if (new_id == (uint16_t)(-1)) {
        free(new);
        return NULL;
    }
    new->inst_id = new_id;
    new->node = node;
    /* Link it */
    /* SHOULD LOCK */
    if (node->inst_last == NULL)
        node->instances = new;
    else
        node->inst_last->next = new;
    node->inst_last = new;

    return new;
}

__attribute__ (( section (".OpenFirmware") ))
static uint32_t OF_instance_get_id (unused OF_env_t *env, OF_inst_t *instance)
{
    OF_DPRINTF("p: %0x i: %0x\n", instance->node->pack_id, instance->inst_id);
    return (instance->node->pack_id << 16) | instance->inst_id;
}

__attribute__ (( section (".OpenFirmware") ))
static OF_inst_t *OF_inst_find (OF_env_t *env, uint32_t ihandle)
{
    OF_node_t *node;
    OF_inst_t *parse;
    uint16_t phandle = ihandle >> 16;

    ihandle &= 0xFFFF;
    OF_DPRINTF("p: %0x i: %0x\n", phandle, ihandle);
    if (ihandle > OF_MAX_PACKAGE)
        return NULL;
    node = OF_pack_find(env, phandle);
    if (node == NULL)
        return NULL;
    for (parse = node->instances; parse != NULL; parse = parse->next) {
        if (parse->inst_id == ihandle)
            return parse;
    }

    return NULL;
}

#if 0
__attribute__ (( section (".OpenFirmware") ))
static OF_inst_t *OF_inst_get_child (OF_env_t *env, OF_node_t *parent,
                                     const uint32_t handle)
{
    OF_node_t *parse, *tmp;

    for (parse = parent->children; parse != NULL; parse = parse->next) {
        if (parse->pack_id == (handle >> 16)) {
            return NULL;
        }
        tmp = OF_inst_get_child(env, parse, handle);
        if (tmp != NULL)
            return tmp;
    }

    return NULL;
}

__attribute__ (( section (".OpenFirmware") ))
static OF_inst_t *OF_inst_get (OF_env_t *env, const unsigned char *name)
{
    return _OF_node_get(env, &OF_node_root);
    
}
#endif

#if 0
__attribute__ (( section (".OpenFirmware") ))
int get_node_name (OF_env_t *env, unsigned char *name,
                   int len, OF_node_t *node)
{
    int tmp, total;
    int i;

    /* Set up manufacturer name */
    total = 0;
    tmp = 0;
#if 0
    if (OF_node_parent(env, node) == NULL ||
        node->manufct != OF_node_parent(env, node)->manufct) {
        tmp = strlen(node->manufct);
        if ((tmp + 2) > len)
            return -1;
        memcpy(name, node->manufct, tmp);
        name += tmp;
    } else if (len < 2) {
        return -1;
    }
    *name++ = ',';
    len -= tmp + 1;
    total += tmp + 1;
#endif
    /* Set up device model */
    tmp = strlen(node->name);
    if ((tmp + 2) > len)
        return -1;
    memcpy(name, node->model, tmp);
    name += tmp;
    *name++ = '@';
    len -= tmp + 1;
    total += tmp + 1;
    /* Set up unit address */
    tmp = strlen(node->address);
    if ((tmp + 2) > len)
        return -1;
    memcpy(name, node->address, tmp);
    name += tmp;
    *name++ = ':';
    len -= tmp + 1;
    total += tmp + 1;
    for (i = 0; node->arguments[i] != NULL; i++) {
        if (i != 0)
            *name++ = ',';
        tmp = strlen(node->arguments[i]);
        if ((tmp + 2) > len)
            return -1;
        memcpy(name, node->arguments[i], tmp);
        name += tmp;
        len -= tmp + 1;
        total += tmp + 1;
    }
    *name = '\0';

    return total;
}
#endif

__attribute__ (( section (".OpenFirmware") ))
static int OF_pack_get_path (OF_env_t *env, unsigned char *name,
                             int len, OF_node_t *node)
{
    OF_prop_t *prop_name, *prop_address;
    uint32_t address;
    int tmp, nlen;

    /* Recurse until we reach the root node */
    OF_DPRINTF("look for [%s]\n", node->prop_name->value);
    if (OF_node_parent(env, node) == NULL) {
        name[0] = '/';
        tmp = 0;
        nlen = 1;
    } else {
        tmp = OF_pack_get_path(env, name, len, OF_node_parent(env, node));
        /* Add node name */
        prop_name = node->prop_name;
        prop_address = node->prop_address;
#if 1
        OF_DPRINTF("Found [%s]\n", prop_name->value);
#endif
        if ((len - tmp) < 2) {
            OF_DPRINTF("Buffer too short (%d 2)\n", len - tmp);
            return 0;
        }
        if (prop_name == NULL) {
            printf("No name in node !\n");
            bug();
        }
        nlen = strlen(prop_name->value);
#if 1
        OF_DPRINTF("got '%s' for '%s' parent (%d %d)\n",
                   name, prop_name->value, tmp, nlen);
#endif
        if (name[tmp - 1] != '/') {
            name[tmp] = '/';
            tmp++;
        }
        address = *((uint32_t *)prop_address->value);
        if (address != OF_ADDRESS_NONE) {
            if ((len - tmp - nlen) < 10) {
                OF_DPRINTF("Buffer too short (%d %d)\n", len - tmp, nlen + 10);
                return 0;
            }
        } else {
            if ((len - tmp - nlen) < 1) {
                OF_DPRINTF("Buffer too short (%d %d)\n", len - tmp, nlen + 1);
                return 0;
            }
        }
        memcpy(name + tmp, prop_name->value, nlen);
        if (address != OF_ADDRESS_NONE) {
            OF_DPRINTF("Add address 0x%08x\n", address);
            sprintf(name + tmp + nlen, "@%x", address);
            nlen += strlen(name + tmp + nlen);
        } else {
            OF_DPRINTF("No address....\n");
        }
    }
    name[tmp + nlen] = '\0';
    OF_DPRINTF("stored [%d]\n", tmp + nlen);
    OF_DUMP_STRING(env, name);
#if 1
    OF_DPRINTF("name '%s' => '%s' %d\n",
               node->properties->value, name, tmp + nlen);
#endif

    return tmp + nlen;
}

__attribute__ (( section (".OpenFirmware") ))
static int OF_inst_get_path (OF_env_t *env, unsigned char *name,
                             int len, OF_inst_t *inst)
{
    return OF_pack_get_path(env, name, len, inst->node);
}

/*****************************************************************************/
/*                       Open firmware C interface                           */
static void OF_serial_write (OF_env_t *OF_env);
static void OF_serial_read (OF_env_t *OF_env);
static void OF_mmu_translate (OF_env_t *OF_env);
static void OF_mmu_map (OF_env_t *OF_env);
static void RTAS_instantiate (OF_env_t *RTAS_env);

static OF_env_t *OF_env_main;

/* Init standard OF structures */
__attribute__ (( section (".OpenFirmware") ))
int OF_init (void)
{
#if 0
        "PowerMac3,1\0MacRISC\0Power Macintosh\0";
        "PowerMac1,2\0MacRISC\0Power Macintosh\0";
        "AAPL,PowerMac G3\0PowerMac G3\0MacRISC\0Power Macintosh\0";
        "AAPL,PowerMac3,0\0MacRISC\0Power Macintosh\0";
        "AAPL,Gossamer\0MacRISC\0Power Macintosh\0";
#endif
    OF_env_t *OF_env;
    OF_node_t *als, *opt, *chs, *pks;
    OF_inst_t *inst;
    OF_range_t range;

    OF_DPRINTF("start\n");
    OF_env_main = malloc(sizeof(OF_env_t));
    if (OF_env_main == NULL) {
        ERROR("%s cannot allocate main OF env\n", __func__);
        return -1;
    }
    //    memset(OF_env_main, 0, sizeof(OF_env_t));
    OF_env = OF_env_main;
    //    OF_env_init(OF_env);

    OF_DPRINTF("start\n");
    /* Set up standard IEEE 1275 nodes */
    /* "/device-tree" */
    OF_node_root = OF_node_new(OF_env, NULL, "device-tree", OF_ADDRESS_NONE);
    if (OF_node_root == NULL) {
        ERROR("Cannot create 'device-tree'\n");
        return -1;
    }
    OF_prop_string_new(OF_env, OF_node_root, "device_type", "bootrom");
    if (arch == ARCH_HEATHROW) {
        const unsigned char compat_str[] =
            "PowerMac1,1\0MacRISC\0Power Macintosh";
        OF_property_new(OF_env, OF_node_root, "compatible",
                        compat_str, sizeof(compat_str));
    OF_prop_string_new(OF_env, OF_node_root,
                           "model", "Power Macintosh");
    } else {
        const unsigned char compat_str[] =
            "PowerMac3,1\0MacRISC\0Power Macintosh";
    OF_property_new(OF_env, OF_node_root, "compatible",
                    compat_str, sizeof(compat_str));
        OF_prop_string_new(OF_env, OF_node_root,
                           "model", "PowerMac3,1");
    }
#if 0
    OF_prop_string_new(OF_env, OF_node_root, "copyright", copyright);
#else
    OF_prop_string_new(OF_env, OF_node_root, "copyright",
            "Copyright 1983-1999 Apple Computer, Inc. All Rights Reserved");
#endif
    OF_prop_string_new(OF_env, OF_node_root, "system-id", "42");
    OF_prop_int_new(OF_env, OF_node_root, "#address-cells", 1);
    OF_prop_int_new(OF_env, OF_node_root, "#size-cells", 1);
    OF_prop_int_new(OF_env, OF_node_root, "clock-frequency", 0x05F03E4D);
    /* "/aliases" node */
    als = OF_node_new(OF_env, OF_node_root, "aliases", OF_ADDRESS_NONE);
    if (als == NULL) {
        ERROR("Cannot create 'aliases'\n");
        return -1;
    }
    /* "/chosen" node */
    chs = OF_node_new(OF_env, OF_node_root, "chosen", OF_ADDRESS_NONE);
    if (chs == NULL) {
        ERROR("Cannot create 'choosen'\n");
        return -1;
    }
    /* "/packages" node */
    pks = OF_node_new(OF_env, OF_node_root, "packages", OF_ADDRESS_NONE);
    if (pks == NULL) {
        ERROR("Cannot create 'packages'\n");
        return -1;
    }
    /* "/cpus" node */
    {
        OF_node_t *cpus;
        cpus = OF_node_new(OF_env, OF_node_root, "cpus", OF_ADDRESS_NONE);
        if (cpus == NULL) {
            ERROR("Cannot create 'cpus'\n");
            return -1;
        }
        OF_prop_int_new(OF_env, cpus, "#address-cells", 1);
        OF_prop_int_new(OF_env, cpus, "#size-cells", 0);
        OF_node_put(OF_env, cpus);
    }
    /* "/memory@0" node */
    {
        OF_node_t *mem;
        mem = OF_node_new(OF_env, OF_node_root, "memory", 0);
        if (mem == NULL) {
            ERROR("Cannot create 'memory'\n");
            return -1;
        }
        OF_prop_string_new(OF_env, mem, "device_type", "memory");
        OF_prop_int_new(OF_env, chs, "memory", OF_pack_handle(OF_env, mem));
        OF_node_put(OF_env, mem);
    }
    /* "/openprom" node */
    {
        OF_node_t *opp;
        opp = OF_node_new(OF_env, OF_node_root, "openprom", OF_ADDRESS_NONE);
        if (opp == NULL) {
            ERROR("Cannot create 'openprom'\n");
            return -1;
        }
        OF_prop_string_new(OF_env, opp, "device_type", "BootROM");
        OF_prop_string_new(OF_env, opp, "model", "OpenFirmware 3");
        OF_prop_int_new(OF_env, opp, "boot-syntax", 0x0001);
        OF_property_new(OF_env, opp, "relative-addressing", NULL, 0);
        OF_property_new(OF_env, opp, "supports-bootinfo", NULL, 0);
        OF_prop_string_new(OF_env, opp, "built-on", stringify(BUILD_DATE));
        OF_prop_string_new(OF_env, als, "rom", "/openprom");
        OF_node_put(OF_env, opp);
    }
    /* "/options" node */
    opt = OF_node_new(OF_env, OF_node_root, "options", OF_ADDRESS_NONE);
    if (opt == NULL) {
        ERROR("Cannot create 'options'\n");
        return -1;
    }
    OF_prop_string_new(OF_env, opt, "little-endian?", "false");
    OF_prop_string_new(OF_env, opt, "real-mode?", "false");
    // Will play with this...
    OF_prop_string_new(OF_env, opt, "security-mode", "none");
    /* "/rom@ff800000" node */
    {
        OF_regprop_t regs;
        OF_node_t *rom, *brom;

        rom = OF_node_new(OF_env, OF_node_root, "rom", 0xff800000);
        if (rom == NULL) {
            ERROR("Cannot create 'rom'\n");
            return -1;
        }
        regs.address = 0xFF800000;
        regs.size = 0x00000000;
        OF_property_new(OF_env, rom, "reg", &regs, sizeof(OF_regprop_t));
        range.virt = 0xFF800000;
        range.phys = 0xFF800000;
        range.size = 0x00800000;
        OF_property_new(OF_env, rom, "ranges", &range, sizeof(OF_range_t));
        OF_prop_int_new(OF_env, rom, "#address-cells", 1);

        /* "/rom/boot-rom@fff00000" node */
        brom = OF_node_new(OF_env, rom, "boot-rom", 0xfff00000);
        if (brom == NULL) {
            ERROR("Cannot create 'boot-rom'\n");
            return -1;
        }
        regs.address = 0xFFF00000;
        regs.size = 0x00100000;
        OF_property_new(OF_env, brom, "reg", &regs, sizeof(OF_regprop_t));
        OF_prop_string_new(OF_env, brom, "write-characteristic", "flash");
        OF_prop_string_new(OF_env, brom, "BootROM-build-date",
                           stringify(BUILD_DATE) " at " stringify(BUILD_TIME));
        OF_prop_string_new(OF_env, brom, "BootROM-version", BIOS_VERSION);
        OF_prop_string_new(OF_env, brom, "copyright", copyright);
        OF_prop_string_new(OF_env, brom, "model", BIOS_str);
        OF_prop_int_new(OF_env, brom, "result", 0);
#if 1
        {
            /* Hack taken 'as-is' from PearPC */
            unsigned char info[] = {
                0xff, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00,
                0x00, 0x01, 0x12, 0xf2, 0x19, 0x99, 0x08, 0x19,
                0x94, 0x4e, 0x73, 0x27, 0xff, 0xf0, 0x80, 0x00,
                0x00, 0x07, 0x80, 0x01, 0x00, 0x01, 0x12, 0xf2,
                0x19, 0x99, 0x08, 0x19, 0xd7, 0xf3, 0xfc, 0x17,
                0xff, 0xf8, 0x00, 0x00, 0x00, 0x08, 0x00, 0x02,
                0x00, 0x01, 0x12, 0xf2, 0x19, 0x99, 0x08, 0x19,
                0xbb, 0x10, 0xfc, 0x17,
            };
            OF_property_new(OF_env, brom, "info", info, sizeof(info));
        }
#endif
        OF_node_put(OF_env, brom);
        OF_node_put(OF_env, rom);
    }
#if 0
    /* From here, hardcoded hacks to get a Mac-like machine */
    /* XXX: Core99 does not seem to like this NVRAM tree */
    /* "/nvram@fff04000" node */
    {
        OF_regprop_t regs;
        OF_node_t *nvr;

        nvr = OF_node_new(OF_env, OF_node_root, "nvram", 0xfff04000);
        if (nvr == NULL) {
            ERROR("Cannot create 'nvram'\n");
            return -1;
        }
        OF_prop_string_new(OF_env, nvr, "device_type", "nvram");
        /* XXX: use real NVRAM size instead */
        OF_prop_int_new(OF_env, nvr, "#bytes", 0x2000);
        OF_prop_string_new(OF_env, nvr, "compatible", "nvram,flash");
        regs.address = 0xFFF04000;
        regs.size = 0x00004000; /* Strange, isn't it ? */
        OF_property_new(OF_env, nvr, "reg", &regs, sizeof(regs));
        OF_prop_int_new(OF_env, chs, "nvram", OF_pack_handle(OF_env, nvr));
        OF_node_put(OF_env, nvr);
    }
#endif
    /* "/pseudo-hid" : hid emulation as Apple does */
    {
        OF_node_t *hid;

        hid = OF_node_new(OF_env, OF_node_root,
                          "pseudo-hid", OF_ADDRESS_NONE);
        if (hid == NULL) {
            ERROR("Cannot create 'pseudo-hid'\n");
            return -1;
        }
        
        /* "keyboard" node */
        {
            OF_node_t *kbd;
            kbd = OF_node_new(OF_env, hid, "keyboard", OF_ADDRESS_NONE);
            if (kbd == NULL) {
                ERROR("Cannot create 'keyboard'\n");
                return -1;
            }
            OF_prop_string_new(OF_env, kbd, "device_type", "keyboard");
            OF_node_put(OF_env, kbd);
        }
        /* "mouse" node */
        {
            OF_node_t *mouse;
            mouse = OF_node_new(OF_env, hid, "mouse", OF_ADDRESS_NONE);
            if (mouse == NULL) {
                ERROR("Cannot create 'mouse'\n");
                return -1;
            }
            OF_prop_string_new(OF_env, mouse, "device_type", "mouse");
            OF_node_put(OF_env, mouse);
        }
        /* "eject-key" node */
        {
            OF_node_t *ejk;
            ejk = OF_node_new(OF_env, hid, "eject-key", OF_ADDRESS_NONE);
            if (ejk == NULL) {
                ERROR("Cannot create 'eject-key'\n");
                return -1;
            }
            OF_prop_string_new(OF_env, ejk, "device_type", "eject-key");
            OF_node_put(OF_env, ejk);
        }
        OF_node_put(OF_env, hid);
    }
    if (arch == ARCH_MAC99) {
        OF_node_t *unin;
        OF_regprop_t regs;

        unin = OF_node_new(OF_env, OF_node_root,
                           "uni-n", 0xf8000000);
        if (unin == NULL) {
            ERROR("Cannot create 'uni-n'\n");
            return -1;
        }
        OF_prop_string_new(OF_env, unin, "device-type", "memory-controller");
        OF_prop_string_new(OF_env, unin, "model", "AAPL,UniNorth");
        OF_prop_string_new(OF_env, unin, "compatible", "uni-north");
        regs.address = 0xf8000000;
        regs.size = 0x01000000;
        OF_property_new(OF_env, unin, "reg", &regs, sizeof(regs));
        OF_prop_int_new(OF_env, unin, "#address-cells", 1);
        OF_prop_int_new(OF_env, unin, "#size-cells", 1);
        OF_prop_int_new(OF_env, unin, "device-rev", 3);
        OF_node_put(OF_env, unin);
    }
    
#if 1 /* This is mandatory for claim to work
       * but I don't know where it should really be (in cpu ?)
       */
    {
        OF_node_t *mmu;

        /* "/mmu" node */
        mmu = OF_node_new(OF_env, OF_node_root, "mmu", OF_ADDRESS_NONE);
        if (mmu == NULL) {
            ERROR("Cannot create 'mmu'\n");
            return -1;
        }
        inst = OF_instance_new(OF_env, mmu);
        if (inst == NULL) {
            OF_node_put(OF_env, mmu);
            ERROR("Cannot create 'mmu' instance\n");
            return -1;
        }
        OF_prop_int_new(OF_env, chs, "mmu",
                        OF_instance_get_id(OF_env, inst));
        OF_method_new(OF_env, mmu, "translate", &OF_mmu_translate);
        OF_method_new(OF_env, mmu, "map", &OF_mmu_map);
        OF_node_put(OF_env, mmu);
    }
#endif

    /* "/options/boot-args" node */
    {
        //        const unsigned char *args = "-v rootdev cdrom";
        //const unsigned char *args = "-v io=0xffffffff";
        const unsigned char *args = "-v";
        /* Ask MacOS X to print debug messages */
        //        OF_prop_string_new(OF_env, chs, "machargs", args);
        //        OF_prop_string_new(OF_env, opt, "boot-command", args);
        OF_prop_string_new(OF_env, opt, "boot-args", args);
    }
    
    /* Release nodes */
    OF_node_put(OF_env, opt);
    OF_node_put(OF_env, pks);
    OF_node_put(OF_env, chs);
    OF_node_put(OF_env, als);
    OF_node_put(OF_env, OF_node_root);
    OF_DPRINTF("done\n");
    
    return 0;
}

/* Motherboard */
#if 0 // For now, static values are used
__attribute__ (( section (".OpenFirmware") ))
int OF_register_mb (const unsigned char *model, const unsigned char **compats)
{
    OF_env_t *OF_env;
    OF_node_t *root;
    int i;
    
    OF_env = OF_env_main;
    OF_DPRINTF("start\n");
    root = OF_node_get(OF_env, "device_tree");
    if (root == NULL) {
        ERROR("Cannot get 'device-tree'\n");
        return -1;
    }
    OF_DPRINTF("add model\n");
    OF_prop_string_new(OF_env, OF_node_root, "model", model);
    for (i = 0; i < 1 && compats[i] != NULL; i++) {
        OF_DPRINTF("add compats %s\n", compats[i]);
        OF_set_compatibility(OF_env, OF_node_root, compats[i]);
    }
    /* we don't implement neither "l2-cache" nor "cache" nodes */
    OF_node_put(OF_env, root);
    OF_DPRINTF("done\n");

    return 0;
}
#endif

/* CPU */
__attribute__ (( section (".OpenFirmware") ))
int OF_register_cpu (const unsigned char *name, int num, uint32_t pvr,
                     uint32_t min_freq, uint32_t max_freq, uint32_t bus_freq,
                     uint32_t tb_freq, uint32_t reset_io)
{
    unsigned char tmp[OF_NAMELEN_MAX];
    OF_env_t *OF_env;
    OF_node_t *cpus, *cpu, *l2c, *chs, *als;

    OF_env = OF_env_main;
    OF_DPRINTF("start\n");
    cpus = OF_node_get(OF_env, "cpus");
    if (cpus == NULL) {
        ERROR("Cannot get 'cpus'\n");
        return -1;
    }
    cpu = OF_node_new(OF_env, cpus, name, OF_ADDRESS_NONE);
    if (cpu == NULL) {
        OF_node_put(OF_env, cpus);
        ERROR("Cannot create cpu '%s'\n", name);
        return -1;
    }
    OF_prop_string_new(OF_env, cpu, "device_type", "cpu");
    OF_prop_int_new(OF_env, cpu, "#address-cells", 0x00000001);
    OF_prop_int_new(OF_env, cpu, "#size-cells", 0x00000000);
    OF_prop_int_new(OF_env, cpu, "reg", num);
    OF_prop_int_new(OF_env, cpu, "cpu-version", pvr);
    OF_prop_int_new(OF_env, cpu, "clock-frequency", max_freq);
    OF_prop_int_new(OF_env, cpu, "timebase-frequency", tb_freq);
    OF_prop_int_new(OF_env, cpu, "bus-frequency", bus_freq);
    OF_prop_int_new(OF_env, cpu, "min-clock-frequency", min_freq);
    OF_prop_int_new(OF_env, cpu, "max-clock-frequency", max_freq);
    OF_prop_int_new(OF_env, cpu, "tlb-size", 0x80);
    OF_prop_int_new(OF_env, cpu, "tlb-sets", 0x40);
    OF_prop_int_new(OF_env, cpu, "i-tlb-size", 0x40);
    OF_prop_int_new(OF_env, cpu, "i-tlb-sets", 0x20);
    OF_prop_int_new(OF_env, cpu, "i-cache-size", 0x8000);
    OF_prop_int_new(OF_env, cpu, "i-cache-sets", 0x80);
    OF_prop_int_new(OF_env, cpu, "i-cache-bloc-size", 0x20);
    OF_prop_int_new(OF_env, cpu, "i-cache-line-size", 0x20);
    OF_prop_int_new(OF_env, cpu, "d-tlb-size", 0x40);
    OF_prop_int_new(OF_env, cpu, "d-tlb-sets", 0x20);
    OF_prop_int_new(OF_env, cpu, "d-cache-size", 0x8000);
    OF_prop_int_new(OF_env, cpu, "d-cache-sets", 0x80);
    OF_prop_int_new(OF_env, cpu, "d-cache-bloc-size", 0x20);
    OF_prop_int_new(OF_env, cpu, "d-cache-line-size", 0x20);
    OF_prop_int_new(OF_env, cpu, "reservation-granule-size", 0x20);
    OF_prop_int_new(OF_env, cpus, "soft-reset", reset_io);
    OF_prop_string_new(OF_env, cpus, "graphics", "");
    OF_prop_string_new(OF_env, cpus, "performance-monitor", "");
    OF_prop_string_new(OF_env, cpus, "data-streams", "");
    OF_prop_string_new(OF_env, cpu, "state", "running");
    /* We don't implement:
     * "dynamic-powerstep" & "reduced-clock-frequency"
     * "l2cr-value"
     */
    /* Add L2 cache */
    l2c = OF_node_new(OF_env, cpu, "l2cache", OF_ADDRESS_NONE);
    if (l2c == NULL) {
        ERROR("Cannot create 'l2cache'\n");
        return -1;
    }
    OF_prop_string_new(OF_env, l2c, "device_type", "cache");
    OF_prop_int_new(OF_env, l2c, "i-cache-size", 0x100000);
    OF_prop_int_new(OF_env, l2c, "i-cache-sets", 0x2000);
    OF_prop_int_new(OF_env, l2c, "i-cache-line-size", 0x40);
    OF_prop_int_new(OF_env, l2c, "d-cache-size", 0x100000);
    OF_prop_int_new(OF_env, l2c, "d-cache-sets", 0x2000);
    OF_prop_int_new(OF_env, l2c, "d-cache-line-size", 0x40);
    /* Register it in the cpu node */
    OF_prop_int_new(OF_env, cpu, "l2-cache", OF_pack_handle(OF_env, l2c));
    OF_node_put(OF_env, l2c);
    /* Set it in "/chosen" and "/aliases" */
    if (num == 0) {
        OF_pack_get_path(OF_env, tmp, 512, cpu);
        chs = OF_node_get(OF_env, "chosen");
        if (chs == NULL) {
            OF_node_put(OF_env, cpus);
            ERROR("Cannot get 'chosen'\n");
            return -1;
        }
        OF_prop_int_new(OF_env, chs, "cpu", OF_pack_handle(OF_env, cpu));
        OF_node_put(OF_env, chs);
        als = OF_node_get(OF_env, "aliases");
        if (als == NULL) {
            OF_node_put(OF_env, cpus);
            ERROR("Cannot get 'aliases'\n");
            return -1;
        }
        OF_prop_string_new(OF_env, als, "cpu", tmp);
        OF_node_put(OF_env, als);
    }
    OF_node_put(OF_env, cpu);
    OF_node_put(OF_env, cpus);
    OF_DPRINTF("done\n");

    return 0;
}

__attribute__ (( section (".OpenFirmware") ))
int OF_register_translations (int nb, OF_transl_t *translations)
{
    OF_env_t *OF_env;
    OF_node_t *cpus, *cpu;
    OF_transl_t *new;
    int i;

    OF_env = OF_env_main;
    OF_DPRINTF("start\n");
    cpus = OF_node_get(OF_env, "cpus");
    if (cpus == NULL) {
        OF_node_put(OF_env, cpus);
        ERROR("Cannot get 'cpus'\n");
        return -1;
    }
    cpu = cpus->children;
    new = malloc(nb * sizeof(OF_transl_t));
    if (new == NULL) {
        ERROR("Cannot create new translation\n");
        return -1;
    }
    for (i = 0; i < nb; i++) {
        new->virt = translations[i].virt;
        new->size = translations[i].size;
        new->phys = translations[i].phys;
        new->mode = translations[i].mode;
        OF_DPRINTF("%d\n", i);
    }
    OF_property_new(OF_env, cpu, "translations",
                    new, nb * sizeof(OF_transl_t));
    OF_node_put(OF_env, cpus);
    OF_DPRINTF("done\n");
    
    return 0;
}

/* Memory ranges */
typedef struct OF_mem_t OF_mem_t;
struct OF_mem_t {
    uint32_t start;
    uint32_t size;
};

#define OF_MAX_MEMRANGES 16
/* First entry is the whole known memory space */
static OF_mem_t OF_mem_ranges[OF_MAX_MEMRANGES + 1];

__attribute__ (( section (".OpenFirmware") ))
int OF_register_memory (uint32_t memsize, unused uint32_t bios_size)
{
    OF_env_t *OF_env;
    OF_node_t *mem;
    OF_regprop_t regs[4];
    int i;

    OF_env = OF_env_main;
    OF_DPRINTF("find node\n");
    mem = OF_node_get(OF_env, "memory");
    if (mem == NULL) {
        ERROR("Cannot get 'memory'\n");
        return -1;
    }
    OF_DPRINTF("Memory package: %04x\n", OF_pack_handle(OF_env, mem));
    regs[0].address = 0x00000000;
    regs[0].size = memsize;
    regs[1].address = 0x00000000;
    regs[1].size = 0x00000000;
    regs[2].address = 0x00000000;
    regs[2].size = 0x00000000;
    regs[3].address = 0x00000000;
    regs[3].size = 0x00000000;
    OF_property_new(OF_env, mem, "reg", regs, 4 * sizeof(OF_regprop_t));
#if 0
#if 1
    regs[0].address = 0x00000000;
    regs[0].size = 0x05800000;
    regs[1].address = 0x06000000;
    regs[1].size = memsize - 0x06000000;
    regs[2].address = 0x00000000;
    regs[2].size = 0x00000000;
    OF_property_new(OF_env, mem, "available",
                    regs, 3 * sizeof(OF_regprop_t));
#else
    regs[0].address = 0x06000000;
    regs[0].size = memsize - 0x06000000;
    regs[1].address = 0x00000000;
    regs[1].size = 0x00000000;
    OF_property_new(OF_env, mem, "available",
                    regs, 2 * sizeof(OF_regprop_t));
#endif
#endif
    OF_node_put(OF_env, mem);
#if 0
    {
        OF_node_t *mmu;
        mmu = OF_node_get(OF_env, "mmu");
        if (mmu == NULL) {
            ERROR("Cannot get 'mmu'\n");
            return -1;
        }
        regs[0].address = 0x00000000;
        regs[0].size = memsize;
        OF_property_new(OF_env, mmu, "reg", regs, sizeof(OF_regprop_t));
        regs[0].address = 0x00000000;
        regs[0].size = 0x05800000;
        regs[1].address = 0x06000000;
        regs[1].size = memsize - 0x06000000;
        regs[2].address = 0x00000000;
        regs[2].size = 0x00000000;
        OF_property_new(OF_env, mmu, "available",
                        regs, 3 * sizeof(OF_regprop_t));
        OF_node_put(OF_env, mmu);
    }
#endif
    /* Also update the claim areas */
    OF_mem_ranges[0].start = 0x00000000;
    OF_mem_ranges[0].size = memsize;
    OF_mem_ranges[1].start = 0x58000000;
    OF_mem_ranges[1].size = 0x08000000;
    for (i = 2; i < OF_MAX_MEMRANGES + 1; i++) {
        OF_mem_ranges[i].start = -1;
        OF_mem_ranges[i].size = -1;
    }
    OF_DPRINTF("done\n");

    return 0;
}

/* Linux kernel command line */
__attribute__ (( section (".OpenFirmware") ))
int OF_register_bootargs (const unsigned char *bootargs)
{
    OF_env_t *OF_env;
    OF_node_t *chs;

    OF_env = OF_env_main;
    if (bootargs == NULL)
        bootargs = "";
    chs = OF_node_get(OF_env, "chosen");
    if (chs == NULL) {
        ERROR("Cannot get 'chosen'\n");
        return -1;
    }
    OF_prop_string_set(OF_env, chs, "bootargs", bootargs);
    //        OF_prop_string_set(OF_env, OF_node_root, "bootargs", "");
    OF_node_put(OF_env, chs);

    return 0;
}

__attribute__ (( section (".OpenFirmware") ))
static void *OF_pci_device_new (OF_env_t *OF_env, OF_node_t *parent,
                                pci_dev_t *dev, uint32_t address,
                                uint16_t rev, uint32_t ccode,
                                uint16_t min_grant, uint16_t max_latency)
{
    OF_node_t *node;

    dprintf("register '%s' '%s' '%s' '%s' 0x%08x in '%s' 0x%08x\n",
           dev->name, dev->type, dev->compat, dev->model, address,
           parent->prop_name->value, *(uint32_t *)parent->prop_address->value);
    node = OF_node_new(OF_env, parent, dev->name, address);
    if (node == NULL)
        return NULL;
    OF_prop_int_new(OF_env, node, "vendor-id", dev->vendor);
    OF_prop_int_new(OF_env, node, "device-id", dev->product);
    OF_prop_int_new(OF_env, node, "revision-id", rev);
    OF_prop_int_new(OF_env, node, "class-code", ccode);
    OF_prop_int_new(OF_env, node, "min-grant", min_grant);
    OF_prop_int_new(OF_env, node, "max-latency", max_latency);
    if (dev->type != NULL)
        OF_prop_string_new1(OF_env, node, "device_type", dev->type);
    if (dev->compat != NULL)
        OF_prop_string_new1(OF_env, node, "compatible", dev->compat);
    if (dev->model != NULL)
        OF_prop_string_new1(OF_env, node, "model", dev->model);
    if (dev->acells != 0)
        OF_prop_int_new(OF_env, node, "#address-cells", dev->acells);
    if (dev->scells != 0)
        OF_prop_int_new(OF_env, node, "#size-cells", dev->scells);
    if (dev->icells != 0)
        OF_prop_int_new(OF_env, node, "#interrupt-cells", dev->icells);
    dprintf("Done %p %p\n", parent, node);
    
    return node;
}

__attribute__ (( section (".OpenFirmware") ))
void *OF_register_pci_host (pci_dev_t *dev, uint16_t rev, uint32_t ccode,
                            uint32_t cfg_base, uint32_t cfg_len,
                            uint32_t mem_base, uint32_t mem_len,
                            uint32_t io_base, uint32_t io_len,
                            uint32_t rbase, uint32_t rlen,
                            uint16_t min_grant, uint16_t max_latency)
{
    OF_env_t *OF_env;
    pci_range_t ranges[3];
    OF_regprop_t regs[1];
    OF_node_t *pci_host, *als;
    int nranges;
    unsigned char buffer[OF_NAMELEN_MAX];

    OF_env = OF_env_main;
    dprintf("register PCI host '%s' '%s' '%s' '%s'\n",
            dev->name, dev->type, dev->compat, dev->model);
    pci_host = OF_pci_device_new(OF_env, OF_node_root, dev, cfg_base,
                                 rev, ccode, min_grant, max_latency);
    if (pci_host == NULL) {
        ERROR("Cannot create pci host\n");
        return NULL;
    }
    
    als = OF_node_get(OF_env, "aliases");
    if (als == NULL) {
        ERROR("Cannot get 'aliases'\n");
        return NULL;
    }
    sprintf(buffer, "/%s", dev->name);
    OF_prop_string_set(OF_env, als, "pci", buffer);
    OF_node_put(OF_env, als);
    

    regs[0].address = cfg_base;
    regs[0].size = cfg_len;
    OF_property_new(OF_env, pci_host, "reg", regs, sizeof(OF_regprop_t));
    nranges = 0;
    if (rbase != 0x00000000) {
        ranges[nranges].addr.hi  = 0x02000000;
        ranges[nranges].addr.mid = 0x00000000;
        ranges[nranges].addr.lo  = rbase;
        ranges[nranges].phys     = rbase;
        ranges[nranges].size_hi  = 0x00000000;
        ranges[nranges].size_lo  = rlen;
        nranges++;
    }
    if (io_base != 0x00000000) {
        ranges[nranges].addr.hi  = 0x01000000;
        ranges[nranges].addr.mid = 0x00000000;
        ranges[nranges].addr.lo  = 0x00000000;
        ranges[nranges].phys     = io_base;
        ranges[nranges].size_hi  = 0x00000000;
        ranges[nranges].size_lo  = io_len;
        nranges++;
    }
    if (mem_base != 0x00000000) {
        ranges[nranges].addr.hi  = 0x02000000;
        ranges[nranges].addr.mid = 0x00000000;
        ranges[nranges].addr.lo  = mem_base;
        ranges[nranges].phys     = mem_base;
        ranges[nranges].size_hi  = 0x00000000;
        ranges[nranges].size_lo  = mem_len;
        nranges++;
    }
    OF_property_new(OF_env, pci_host, "ranges", ranges,
                    nranges * sizeof(pci_range_t));

    return pci_host;
}

__attribute__ (( section (".OpenFirmware") ))
void *OF_register_pci_bridge (void *parent, pci_dev_t *dev,
                              uint32_t cfg_base, uint32_t cfg_len,
                              uint8_t devfn, uint8_t rev, uint32_t ccode,
                              uint16_t min_grant, uint16_t max_latency)
{
    OF_env_t *OF_env;
    OF_regprop_t regs[1];
    OF_node_t *pci_bridge;

    OF_env = OF_env_main;
    OF_DPRINTF("register '%s' %08x '%s' '%s' '%s'\n",
               dev->name, devfn >> 3, dev->type, dev->compat, dev->model);
    dprintf("register PCI bridge '%s' %08x '%s' '%s' '%s'\n",
            dev->name, devfn >> 3, dev->type, dev->compat, dev->model);
    pci_bridge = OF_pci_device_new(OF_env, parent, dev, devfn >> 3,
                                   rev, ccode, min_grant, max_latency);
    if (pci_bridge == NULL) {
        ERROR("Cannot create pci bridge\n");
        return NULL;
    }
    regs[0].address = cfg_base;
    regs[0].size = cfg_len;
    OF_property_new(OF_env, pci_bridge, "reg", regs, sizeof(OF_regprop_t));

    return pci_bridge;
}

__attribute__ (( section (".OpenFirmware") ))
void *OF_register_pci_device (void *parent, pci_dev_t *dev,
                              uint8_t devfn, uint8_t rev, uint32_t ccode,
                              uint16_t min_grant, uint16_t max_latency)
{
    OF_env_t *OF_env;
    OF_node_t *pci_dev;

    OF_env = OF_env_main;
    OF_DPRINTF("register '%s' %08x '%s' '%s' '%s'\n",
               dev->name, devfn >> 3, dev->type, dev->compat, dev->model);
    dprintf("register pci device '%s' %08x '%s' '%s' '%s'\n",
               dev->name, devfn >> 3, dev->type, dev->compat, dev->model);
    pci_dev = OF_pci_device_new(OF_env, parent, dev, devfn >> 3,
                                rev, ccode, min_grant, max_latency);

    return pci_dev;
}

/* XXX: suppress that, used for interrupt map init */
OF_node_t *pci_host_node;
uint32_t pci_host_interrupt_map[7 * 32];
int pci_host_interrupt_map_len = 0;

void OF_finalize_pci_host (void *dev, int first_bus, int nb_busses)
{
    OF_env_t *OF_env;
    OF_regprop_t regs[1];
    
    OF_env = OF_env_main;
    regs[0].address = first_bus;
    regs[0].size = nb_busses;
    OF_property_new(OF_env, dev, "bus-range", regs, sizeof(OF_regprop_t));
    pci_host_node = dev;
}

void OF_finalize_pci_device (void *dev, uint8_t bus, uint8_t devfn,
                             uint32_t *regions, uint32_t *sizes,
                             int irq_line)
{
    OF_env_t *OF_env;
    pci_reg_prop_t pregs[6], rregs[6];
    uint32_t mask;
    int i, j, k;

    OF_env = OF_env_main;
    /* XXX: only useful for VGA card in fact */
    if (regions[0] != 0x00000000)
        OF_prop_int_set(OF_env, dev, "address", regions[0] & ~0x0000000F);
    for (i = 0, j = 0, k = 0; i < 6; i++) {
        if (regions[i] != 0x00000000 && sizes[i] != 0x00000000) {
            /* Generate "reg" property
             */
            if (regions[i] & 1) {
                /* IO space */
                rregs[j].addr.hi = 0x01000000;
                mask = 0x00000001;
            } else if (regions[i] & 4) {
                /* 64 bits address space */
                rregs[j].addr.hi = 0x83000000;
                mask = 0x0000000F;
#if 0
            } else if ((regions[i] & 0xF) == 0x00) { /* ? */
                /* Configuration space */
                rregs[j].addr.hi = 0x00000000;
                mask = 0x0000000F;
#endif
            } else {
                /* 32 bits address space */
                rregs[j].addr.hi = 0x82000000;
                mask = 0x0000000F;
            }
            /* Set bus number */
            rregs[j].addr.hi |= bus << 16;
            /* Set device/function */
            rregs[j].addr.hi |= devfn << 8;
            /* Set register */
#if 1
            rregs[j].addr.hi |= 0x10 + (i * sizeof(uint32_t)); /* ? */
#endif
            /* Set address */
            rregs[j].addr.mid = 0x00000000;
            rregs[j].addr.lo = regions[i] & ~mask;
            /* Set size */
            rregs[j].size_hi = 0x00000000;
            rregs[j].size_lo = sizes[i];
#if 0
            if ((rregs[j].addr.hi & 0x03000000) != 0x00000000)
#endif
            {
                /* No assigned address for configuration space */
                pregs[k].addr.hi = rregs[j].addr.hi; /* ? */
                pregs[k].addr.mid = rregs[j].addr.mid;
                pregs[k].addr.lo = rregs[j].addr.lo; /* ? */
                pregs[k].size_hi = rregs[j].size_hi;
                pregs[k].size_lo = rregs[j].size_lo;
                k++;
            }
            j++;
        }
    }
    if (j > 0) {
        OF_property_new(OF_env, dev, "reg",
                        rregs, j * sizeof(pci_reg_prop_t));
    } else {
        OF_property_new(OF_env, dev, "reg", NULL, 0);
    }
    if (k > 0) {
        OF_property_new(OF_env, dev, "assigned-addresses",
                        pregs, k * sizeof(pci_reg_prop_t));
    } else {
        OF_property_new(OF_env, dev, "assigned-addresses", NULL, 0);
    }
    if (irq_line >= 0) {
        int i;
        OF_prop_int_new(OF_env, dev, "interrupts", 1);
        i = pci_host_interrupt_map_len;
        pci_host_interrupt_map[i++] = (devfn << 8) & 0xf800;
        pci_host_interrupt_map[i++] = 0;
        pci_host_interrupt_map[i++] = 0;
        pci_host_interrupt_map[i++] = 0;
        pci_host_interrupt_map[i++] = 0; /* pic handle will be patched later */
        pci_host_interrupt_map[i++] = irq_line;
        if (arch != ARCH_HEATHROW) {
            pci_host_interrupt_map[i++] = 1;
        }
        pci_host_interrupt_map_len = i;
    }
#if 1
    {
        OF_prop_t *prop_name = ((OF_node_t *)dev)->prop_name;

        if (j > 0) {
            dprintf("PCI device '%s' %d %d %d reg properties:\n",
                    prop_name->value, bus, devfn >> 3, devfn & 7);
            for (i = 0; i < j; i++) {
                dprintf("  addr: %08x %08x %08x size: %08x %08x\n",
                        rregs[i].addr.hi, rregs[i].addr.mid, rregs[i].addr.lo,
                        rregs[i].size_hi, rregs[i].size_lo);
            }
        } else {
            dprintf("PCI device '%s' %d %d %d has no reg properties:\n",
                    prop_name->value, bus, devfn >> 3, devfn & 7);
        }
        if (k > 0) {
            dprintf("PCI device '%s' %d %d %d "
                    "assigned addresses properties:\n",
                    prop_name->value, bus, devfn >> 3, devfn & 7);
            for (i = 0; i < j; i++) {
                dprintf("  addr: %08x %08x %08x size: %08x %08x\n",
                        pregs[i].addr.hi, pregs[i].addr.mid, pregs[i].addr.lo,
                        pregs[i].size_hi, pregs[i].size_lo);
            }
        } else {
            dprintf("PCI device '%s' %d %d %d has no "
                    "assigned addresses properties:\n",
                    prop_name->value, bus, devfn >> 3, devfn & 7);
        }
    }
#endif
}

__attribute__ (( section (".OpenFirmware") ))
int OF_register_bus (const unsigned char *name, uint32_t address,
                     const unsigned char *type)
{
    unsigned char buffer[OF_NAMELEN_MAX];
    OF_env_t *OF_env;
    OF_node_t *bus, *als;
    
    OF_env = OF_env_main;
    als = OF_node_get(OF_env, "aliases");
    if (als == NULL) {
        ERROR("Cannot get 'aliases'\n");
        return -1;
    }
    bus = OF_node_new(OF_env, OF_node_root, name, address);
    if (bus == NULL) {
        OF_node_put(OF_env, als);
        ERROR("Cannot create bus '%s'\n", name);
        return -1;
    }
    OF_prop_string_set(OF_env, bus, "type", type);
    sprintf(buffer, "/%s", name);
    OF_prop_string_set(OF_env, als, name, buffer);
    /* For ISA, should add DMA ranges */
    OF_node_put(OF_env, bus);
    OF_node_put(OF_env, als);

    return 0;
}

// We will need to register stdin & stdout via the serial port
__attribute__ (( section (".OpenFirmware") ))
int OF_register_serial (const unsigned char *bus, const unsigned char *name,
                        uint32_t io_base, unused int irq)
{
    unsigned char tmp[OF_NAMELEN_MAX];
    OF_env_t *OF_env;
    OF_node_t *busn, *srl, *als;

    OF_env = OF_env_main;
    als = OF_node_get(OF_env, "aliases");
    if (als == NULL) {
        ERROR("Cannot get 'aliases'\n");
        return -1;
    }
    busn = OF_node_get(OF_env, bus);
    srl = OF_node_new(OF_env, busn, name, io_base);
    if (srl == NULL) {
        OF_node_put(OF_env, als);
        ERROR("Cannot create serial '%s'\n", name);
        return -1;
    }
    OF_prop_string_set(OF_env, srl, "device_type", "serial");
    OF_prop_string_set(OF_env, srl, "compatible", "pnpPNP,501");
    switch (io_base) {
    case 0x3F8:
        OF_pack_get_path(OF_env, tmp, 512, srl);
        OF_prop_string_new(OF_env, als, "com1", tmp);
        break;
    case 0x2F8:
        OF_pack_get_path(OF_env, tmp, 512, srl);
        OF_prop_string_new(OF_env, als, "com2", tmp);
        break;
    default:
        break;
    }
    /* register read/write methods and create an instance of the package */
    OF_method_new(OF_env, srl, "write", &OF_serial_write);
    OF_method_new(OF_env, srl, "read", &OF_serial_read);
    OF_node_put(OF_env, srl);
    OF_node_put(OF_env, busn);
    OF_node_put(OF_env, als);

    return 0;
}

/* We will also need /isa/rtc */

__attribute__ (( section (".OpenFirmware") ))
int OF_register_stdio (const unsigned char *dev_in,
                       const unsigned char *dev_out)
{
    OF_env_t *OF_env;
    OF_node_t *chs, *ndev_in, *ndev_out, *kbd;
    OF_inst_t *in_inst, *out_inst;
    
    OF_env = OF_env_main;
    chs = OF_node_get(OF_env, "chosen");
    if (chs == NULL) {
        ERROR("Cannot get 'chosen'\n");
        return -1;
    }
    ndev_in = OF_node_get(OF_env, dev_in);
    ndev_out = OF_node_get(OF_env, dev_out);
    in_inst = OF_instance_new(OF_env, ndev_in);
    if (in_inst == NULL) {
        OF_node_put(OF_env, ndev_out);
        OF_node_put(OF_env, ndev_in);
        OF_node_put(OF_env, chs);
        ERROR("Cannot create in_inst\n");
        return -1;
    }
    out_inst = OF_instance_new(OF_env, ndev_out);
    if (out_inst == NULL) {
        OF_node_put(OF_env, ndev_out);
        OF_node_put(OF_env, ndev_in);
        OF_node_put(OF_env, chs);
        ERROR("Cannot create out_inst\n");
        return -1;
    }
    OF_prop_int_set(OF_env, chs, "stdin",
                    OF_instance_get_id(OF_env, in_inst));
    OF_prop_int_set(OF_env, chs, "stdout",
                    OF_instance_get_id(OF_env, out_inst));
    kbd = OF_node_new(OF_env, ndev_in, "keyboard", OF_ADDRESS_NONE);
    if (kbd == NULL) {
        OF_node_put(OF_env, ndev_out);
        OF_node_put(OF_env, ndev_in);
        OF_node_put(OF_env, chs);
        ERROR("Cannot create 'keyboard' for stdio\n");
        return -1;
    }
    OF_prop_string_new(OF_env, kbd, "device_type", "keyboard");
    OF_node_put(OF_env, kbd);
    OF_DPRINTF("stdin h: 0x%0x out : 0x%0x\n",
               OF_instance_get_id(OF_env, in_inst),
               OF_instance_get_id(OF_env, out_inst));
    OF_node_put(OF_env, ndev_out);
    OF_node_put(OF_env, ndev_in);
    OF_node_put(OF_env, chs);

    return 0;
}

static void keylargo_ata(OF_node_t *mio, uint32_t base_address,
                         uint32_t base, int irq1, int irq2, 
                         uint16_t pic_phandle)
{
    OF_env_t *OF_env = OF_env_main;
    OF_node_t *ata;
    OF_regprop_t regs[2];

    ata = OF_node_new(OF_env, mio, "ata-4", base);
    if (ata == NULL) {
        ERROR("Cannot create 'ata-4'\n");
        return;
    }
    OF_prop_string_new(OF_env, ata, "device_type", "ata");
#if 1
    OF_prop_string_new(OF_env, ata, "compatible", "key2largo-ata");
    OF_prop_string_new(OF_env, ata, "model", "ata-4");
    OF_prop_string_new(OF_env, ata, "cable-type", "80-conductor");
#else
    OF_prop_string_new(OF_env, ata, "compatible", "cmd646-ata");
    OF_prop_string_new(OF_env, ata, "model", "ata-4");
#endif
    OF_prop_int_new(OF_env, ata, "#address-cells", 1);
    OF_prop_int_new(OF_env, ata, "#size-cells", 0);
    regs[0].address = base;
    regs[0].size = 0x00001000;
#if 0 // HACK: Don't set up DMA registers
    regs[1].address = 0x00008A00;
    regs[1].size = 0x00001000;
    OF_property_new(OF_env, ata, "reg",
                    regs, 2 * sizeof(OF_regprop_t));
#else
    OF_property_new(OF_env, ata, "reg",
                    regs, sizeof(OF_regprop_t));
#endif
    OF_prop_int_new(OF_env, ata, "interrupt-parent", pic_phandle);
    regs[0].address = irq1;
    regs[0].size = 0x00000001;
    regs[1].address = irq2;
    regs[1].size = 0x00000000;
    OF_property_new(OF_env, ata, "interrupts",
                    regs, 2 * sizeof(OF_regprop_t));
    if (base == 0x1f000)
        ide_pci_pmac_register(base_address + base, 0x00000000, ata);
    else
        ide_pci_pmac_register(0x00000000, base_address + base, ata);
}

void OF_finalize_pci_macio (void *dev, uint32_t base_address, uint32_t size,
                            void *private_data)
{
    unsigned char tmp[OF_NAMELEN_MAX];
    OF_env_t *OF_env;
    pci_reg_prop_t pregs[2];
    OF_node_t *mio, *chs, *als;
    uint16_t pic_phandle;
    int rec_len;
    OF_prop_t *mio_reg;

    OF_DPRINTF("mac-io: %p\n", dev);
    OF_env = OF_env_main;
    chs = OF_node_get(OF_env, "chosen");
    if (chs == NULL) {
        ERROR("Cannot get 'chosen'\n");
        return;
    }
    als = OF_node_get(OF_env, "aliases");
    if (als == NULL) {
        OF_node_put(OF_env, als);
        ERROR("Cannot get 'aliases'\n");
        return;
    }
    /* Mac-IO is mandatory for OSX to boot */
    mio = dev;
    mio->private_data = private_data;
    pregs[0].addr.hi = 0x00000000;
    pregs[0].addr.mid = 0x00000000;
    pregs[0].addr.lo = 0x00000000;
    pregs[0].size_hi = base_address;
    pregs[0].size_lo = size;
    mio_reg = OF_property_get(OF_env, mio, "reg");
    if (mio_reg && mio_reg->vlen >= 5 * 4) {
        pregs[0].addr.mid = ((pci_reg_prop_t *)mio_reg->value)->addr.hi;
    }
    OF_property_new(OF_env, mio, "ranges",
                    &pregs, sizeof(pci_reg_prop_t));
#if 0
    pregs[0].addr.hi = 0x82013810;
    pregs[0].addr.mid = 0x00000000;
    pregs[0].addr.lo = 0x80800000;
    pregs[0].size_hi = 0x00000000;
    pregs[0].size_lo = 0x00080000;
    OF_property_new(OF_env, mio, "assigned-addresses",
                    &pregs, sizeof(pci_reg_prop_t));
#endif

    if (arch == ARCH_HEATHROW) {
        /* Heathrow PIC */
        OF_regprop_t regs;
        OF_node_t *mpic;
        const char compat_str[] = "heathrow\0mac-risc";

        mpic = OF_node_new(OF_env, mio, "interrupt-controller", 0x10);
        if (mpic == NULL) {
            ERROR("Cannot create 'mpic'\n");
            goto out;
        }
        OF_prop_string_new(OF_env, mpic, "device_type", "interrupt-controller");
        OF_property_new(OF_env, mpic, "compatible", compat_str, sizeof(compat_str));
        OF_prop_int_new(OF_env, mpic, "#interrupt-cells", 1);
        regs.address = 0x10;
        regs.size = 0x20;
        OF_property_new(OF_env, mpic, "reg",
                        &regs, sizeof(regs));
        OF_property_new(OF_env, mpic, "interrupt-controller", NULL, 0);
        pic_phandle = OF_pack_handle(OF_env, mpic);
        OF_prop_int_new(OF_env, chs, "interrupt-controller", pic_phandle);
        OF_node_put(OF_env, mpic);
        rec_len = 6;
    } else {
    /* OpenPIC */
        OF_regprop_t regs[4];
        OF_node_t *mpic;
        mpic = OF_node_new(OF_env, mio, "interrupt-controller", 0x40000);
        if (mpic == NULL) {
            ERROR("Cannot create 'mpic'\n");
            goto out;
        }
        OF_prop_string_new(OF_env, mpic, "device_type", "open-pic");
        OF_prop_string_new(OF_env, mpic, "compatible", "chrp,open-pic");
        OF_property_new(OF_env, mpic, "interrupt-controller", NULL, 0);
        OF_property_new(OF_env, mpic, "built-in", NULL, 0);
        OF_prop_int_new(OF_env, mpic, "clock-frequency", 0x003F7A00);
        OF_prop_int_new(OF_env, mpic, "#address-cells", 0);
        OF_prop_int_new(OF_env, mpic, "#interrupt-cells", 2);
        memset(regs, 0, 4 * sizeof(OF_regprop_t));
        regs[0].address = 0x00040000;
        regs[0].size = 0x00040000;
        OF_property_new(OF_env, mpic, "reg",
                        &regs, 1 * sizeof(OF_regprop_t));
        pic_phandle = OF_pack_handle(OF_env, mpic);
        OF_prop_int_new(OF_env, chs, "interrupt-controller", pic_phandle);
        OF_node_put(OF_env, mpic);
        rec_len = 7;
    }

    /* patch pci host table */
    /* XXX: do it after the PCI init */
    {
        int i;
        uint32_t tab[4];

        for(i = 0; i < pci_host_interrupt_map_len; i += rec_len)
            pci_host_interrupt_map[i + 4] = pic_phandle;
#if 0
        dprintf("interrupt-map:\n");
        for(i = 0; i < pci_host_interrupt_map_len; i++) {
            dprintf(" %08x", pci_host_interrupt_map[i]);
            if ((i % rec_len) == (rec_len - 1))
                dprintf("\n");
        }
        dprintf("\n");
#endif
        OF_property_new(OF_env, pci_host_node, "interrupt-map", 
                        pci_host_interrupt_map, 
                        pci_host_interrupt_map_len * sizeof(uint32_t));
        tab[0] = 0xf800;
        tab[1] = 0;
        tab[2] = 0;
        tab[3] = 0;
        OF_property_new(OF_env, pci_host_node, "interrupt-map-mask", 
                        tab, 4 * sizeof(uint32_t));
    }
#if 0
    /* escc is useful to get MacOS X debug messages */
    {
        OF_regprop_t regs[8];
        uint32_t irqs[6];
        OF_node_t *scc, *chann;
        scc = OF_node_new(OF_env, mio, "escc", 0x13000);
        if (scc == NULL) {
            ERROR("Cannot create 'escc'\n");
            goto out;
        }
        OF_prop_string_new(OF_env, scc, "device_type", "escc");
        OF_prop_string_new(OF_env, scc, "compatible", "chrp,es0");
        OF_property_new(OF_env, scc, "built-in", NULL, 0);
        OF_prop_int_new(OF_env, scc, "#address-cells", 1);
        memset(regs, 0, 8 * sizeof(OF_regprop_t));
        regs[0].address = 0x00013000;
        regs[0].size = 0x00001000;
        regs[1].address = 0x00008400;
        regs[1].size = 0x00000100;
        regs[2].address = 0x00008500;
        regs[2].size = 0x00000100;
        regs[3].address = 0x00008600;
        regs[3].size = 0x00000100;
        regs[4].address = 0x00008700;
        regs[4].size = 0x00000100;
        OF_property_new(OF_env, scc, "reg",
                        regs, 5 * sizeof(OF_regprop_t));
        OF_property_new(OF_env, scc, "ranges", NULL, 0);
        /* Set up two channels */
        chann = OF_node_new(OF_env, scc, "ch-a", 0x13020);
        if (chann == NULL) {
            ERROR("Cannot create 'ch-a'\n");
            goto out;
        }
        OF_prop_string_new(OF_env, chann, "device_type", "serial");
        OF_prop_string_new(OF_env, chann, "compatible", "chrp,es2");
        OF_property_new(OF_env, chann, "built-in", NULL, 0);
        OF_prop_int_new(OF_env, chann, "slot-names", 0);
        OF_prop_int_new(OF_env, chann, "interrupt-parent", pic_phandle);
        memset(regs, 0, 8 * sizeof(OF_regprop_t));
        regs[0].address = 0x00013020;
        regs[0].size = 0x00000001;
        regs[1].address = 0x00013030;
        regs[1].size = 0x00000001;
        regs[2].address = 0x00013050;
        regs[2].size = 0x00000001;
        regs[3].address = 0x00008400;
        regs[3].size = 0x00000100;
        regs[4].address = 0x00008500;
        regs[4].size = 0x00000100;
        OF_property_new(OF_env, chann, "reg",
                        regs, 5 * sizeof(OF_regprop_t));
        /* XXX: tofix: those are regprops */
        irqs[0] = 0x16;
        irqs[1] = 0x01;
        irqs[2] = 0x05;
        irqs[3] = 0x00;
        irqs[4] = 0x06;
        irqs[5] = 0x00;
        OF_property_new(OF_env, chann, "interrupts",
                        irqs, 6 * sizeof(uint32_t));
        OF_node_put(OF_env, chann);
        chann = OF_node_new(OF_env, scc, "ch-b", 0x13000);
        if (chann == NULL) {
            ERROR("Cannot create 'ch-b'\n");
            goto out;
        }
        OF_prop_string_new(OF_env, chann, "device_type", "serial");
        OF_prop_string_new(OF_env, chann, "compatible", "chrp,es3");
        OF_property_new(OF_env, chann, "built-in", NULL, 0);
        OF_prop_int_new(OF_env, chann, "slot-names", 0);
        OF_prop_int_new(OF_env, chann, "interrupt-parent", pic_phandle);
        memset(regs, 0, 8 * sizeof(OF_regprop_t));
        regs[0].address = 0x00013000;
        regs[0].size = 0x00000001;
        regs[1].address = 0x00013010;
        regs[1].size = 0x00000001;
        regs[2].address = 0x00013040;
        regs[2].size = 0x00000001;
        regs[3].address = 0x00008600;
        regs[3].size = 0x00000100;
        regs[4].address = 0x00008700;
        regs[4].size = 0x00000100;
        OF_property_new(OF_env, chann, "reg",
                        regs, 5 * sizeof(OF_regprop_t));
        /* XXX: tofix: those are regprops */
        irqs[0] = 0x17;
        irqs[1] = 0x01;
        irqs[2] = 0x07;
        irqs[3] = 0x00;
        irqs[4] = 0x08;
        irqs[5] = 0x00;
        OF_property_new(OF_env, chann, "interrupts",
                        irqs, 6 * sizeof(uint32_t));
        OF_node_put(OF_env, chann);
        OF_node_put(OF_env, scc);
        /* MacOS likes escc-legacy */
        scc = OF_node_new(OF_env, mio, "escc-legacy", 0x12000);
        if (scc == NULL) {
            ERROR("Cannot create 'escc-legacy'\n");
            goto out;
        }
        OF_prop_string_new(OF_env, scc, "device_type", "escc-legacy");
        OF_prop_string_new(OF_env, scc, "compatible", "chrp,es1");
        OF_property_new(OF_env, scc, "built-in", NULL, 0);
        OF_prop_int_new(OF_env, scc, "#address-cells", 1);
        memset(regs, 0, 8 * sizeof(OF_regprop_t));
        regs[0].address = 0x00012000;
        regs[0].size = 0x00001000;
        regs[1].address = 0x00008400;
        regs[1].size = 0x00000100;
        regs[2].address = 0x00008500;
        regs[2].size = 0x00000100;
        regs[3].address = 0x00008600;
        regs[3].size = 0x00000100;
        regs[4].address = 0x00008700;
        regs[4].size = 0x00000100;
        OF_property_new(OF_env, scc, "reg",
                        regs, 8 * sizeof(OF_regprop_t));
        OF_property_new(OF_env, scc, "ranges", NULL, 0);
        /* Set up two channels */
        chann = OF_node_new(OF_env, scc, "ch-a", 0x12004);
        if (chann == NULL) {
            ERROR("Cannot create 'ch-a'\n");
            goto out;
        }
        OF_prop_string_new(OF_env, chann, "device_type", "serial");
        OF_prop_string_new(OF_env, chann, "compatible", "chrp,es4");
        OF_property_new(OF_env, chann, "built-in", NULL, 0);
        OF_prop_int_new(OF_env, chann, "interrupt-parent", pic_phandle);
        memset(regs, 0, 8 * sizeof(OF_regprop_t));
        regs[0].address = 0x00012004;
        regs[0].size = 0x00000001;
        regs[1].address = 0x00012006;
        regs[1].size = 0x00000001;
        regs[2].address = 0x0001200A;
        regs[2].size = 0x00000001;
        regs[3].address = 0x00008400;
        regs[3].size = 0x00000100;
        regs[4].address = 0x00008500;
        regs[4].size = 0x00000100;
        OF_property_new(OF_env, chann, "reg",
                        regs, 8 * sizeof(OF_regprop_t));
        /* XXX: tofix: those are regprops */
        irqs[0] = 0x16;
        irqs[1] = 0x01;
        irqs[2] = 0x05;
        irqs[3] = 0x00;
        irqs[4] = 0x06;
        irqs[5] = 0x00;
        OF_property_new(OF_env, chann, "interrupts",
                        irqs, 6 * sizeof(uint32_t));
        OF_node_put(OF_env, chann);
        chann = OF_node_new(OF_env, scc, "ch-b", 0x12000);
        if (chann == NULL) {
            ERROR("Cannot create 'ch-b'\n");
            goto out;
        }
        OF_prop_string_new(OF_env, chann, "device_type", "serial");
        OF_prop_string_new(OF_env, chann, "compatible", "chrp,es5");
        OF_property_new(OF_env, chann, "built-in", NULL, 0);
        OF_prop_int_new(OF_env, chann, "interrupt-parent", pic_phandle);
        memset(regs, 0, 8 * sizeof(OF_regprop_t));
        regs[0].address = 0x00012000;
        regs[0].size = 0x00000001;
        regs[1].address = 0x00012002;
        regs[1].size = 0x00000001;
        regs[2].address = 0x00012008;
        regs[2].size = 0x00000001;
        regs[3].address = 0x00008600;
        regs[3].size = 0x00000100;
        regs[4].address = 0x00008700;
        regs[4].size = 0x00000100;
        OF_property_new(OF_env, chann, "reg",
                        regs, 8 * sizeof(OF_regprop_t));
        /* XXX: tofix: those are regprops */
        irqs[0] = 0x17;
        irqs[1] = 0x01;
        irqs[2] = 0x07;
        irqs[3] = 0x00;
        irqs[4] = 0x08;
        irqs[5] = 0x00;
        OF_property_new(OF_env, chann, "interrupts",
                        irqs, 6 * sizeof(uint32_t));
        OF_node_put(OF_env, chann);
        OF_node_put(OF_env, scc);
    }
#endif
    /* Keylargo IDE controller: need some work (DMA problem ?) */
    if (arch == ARCH_MAC99) {
        keylargo_ata(mio, base_address, 0x1f000, 0x13, 0xb, pic_phandle);
        keylargo_ata(mio, base_address, 0x20000, 0x14, 0xb, pic_phandle);
    }
#if 0
    /* Timer */
    {
        OF_node_t *tmr;
        OF_regprop_t regs[1];
        tmr = OF_node_new(OF_env, mio, "timer", 0x15000);
        if (tmr == NULL) {
            ERROR("Cannot create 'timer'\n");
            goto out;
        }
        OF_prop_string_new(OF_env, tmr, "device_type", "timer");
        OF_prop_string_new(OF_env, tmr, "compatible", "keylargo-timer");
        OF_prop_int_new(OF_env, tmr, "clock-frequency", 0x01194000);
        regs[0].address = 0x00015000;
        regs[0].size = 0x00001000;
        OF_property_new(OF_env, tmr, "reg", regs, sizeof(OF_regprop_t));
        OF_prop_int_new(OF_env, tmr, "interrupt-parent", pic_phandle);
        regs[0].address = 0x00000020;
        regs[0].size = 0x00000001;
        OF_property_new(OF_env, tmr, "interrupts",
                        regs, sizeof(OF_regprop_t));
        OF_node_put(OF_env, tmr);
    }
#endif
    /* VIA-PMU */
    {
        /* Controls adb, RTC and power-mgt (forget it !) */
        OF_node_t *via, *adb;
        OF_regprop_t regs[1];
#if 0 // THIS IS A HACK AND IS COMPLETELY ABSURD !
      // (but needed has Qemu doesn't emulate via-pmu).
        via = OF_node_new(OF_env, mio, "via-pmu", 0x16000);
        if (via == NULL) {
            ERROR("Cannot create 'via-pmu'\n");
            goto out;
        }
        OF_prop_string_new(OF_env, via, "device_type", "via-pmu");
        OF_prop_string_new(OF_env, via, "compatible", "pmu");
#else
        via = OF_node_new(OF_env, mio, "via-cuda", 0x16000);
        if (via == NULL) {
            ERROR("Cannot create 'via-cuda'\n");
            goto out;
        }
        OF_prop_string_new(OF_env, via, "device_type", "via-cuda");
        OF_prop_string_new(OF_env, via, "compatible", "cuda");
#endif
        regs[0].address = 0x00016000;
        regs[0].size = 0x00002000;
        OF_property_new(OF_env, via, "reg", regs, sizeof(OF_regprop_t));
        OF_prop_int_new(OF_env, via, "interrupt-parent", pic_phandle);
        if (arch == ARCH_HEATHROW) {
            OF_prop_int_new(OF_env, via, "interrupts", 0x12);
        } else {
        regs[0].address = 0x00000019;
        regs[0].size = 0x00000001;
        OF_property_new(OF_env, via, "interrupts",
                        regs, sizeof(OF_regprop_t));
        }
        /* force usage of OF bus speeds */
        OF_prop_int_new(OF_env, via, "BusSpeedCorrect", 1);
#if 0
        OF_prop_int_new(OF_env, via, "pmu-version", 0x00D0740C);
#endif
        {
            OF_node_t *kbd, *mouse;
        /* ADB pseudo-device */
        adb = OF_node_new(OF_env, via, "adb", OF_ADDRESS_NONE);
        if (adb == NULL) {
            ERROR("Cannot create 'adb'\n");
            goto out;
        }
        OF_prop_string_new(OF_env, adb, "device_type", "adb");
#if 0
        OF_prop_string_new(OF_env, adb, "compatible", "pmu-99");
#else
        OF_prop_string_new(OF_env, adb, "compatible", "adb");
#endif
        OF_prop_int_new(OF_env, adb, "#address-cells", 1);
        OF_prop_int_new(OF_env, adb, "#size-cells", 0);
        OF_pack_get_path(OF_env, tmp, 512, adb);
        OF_prop_string_new(OF_env, als, "adb", tmp);

            kbd = OF_node_new(OF_env, adb, "keyboard", 2);
            if (kbd == NULL) {
                ERROR("Cannot create 'kbd'\n");
                goto out;
            }
            OF_prop_string_new(OF_env, kbd, "device_type", "keyboard");
            OF_prop_int_new(OF_env, kbd, "reg", 2);

            mouse = OF_node_new(OF_env, adb, "mouse", 3);
            if (mouse == NULL) {
                ERROR("Cannot create 'mouse'\n");
                goto out;
            }
            OF_prop_string_new(OF_env, mouse, "device_type", "mouse");
            OF_prop_int_new(OF_env, mouse, "reg", 3);
            OF_prop_int_new(OF_env, mouse, "#buttons", 3);
        }
        {
            OF_node_t *rtc;
        
        rtc = OF_node_new(OF_env, via, "rtc", OF_ADDRESS_NONE);
        if (rtc == NULL) {
            ERROR("Cannot create 'rtc'\n");
            goto out;
        }
        OF_prop_string_new(OF_env, rtc, "device_type", "rtc");
#if 0
        OF_prop_string_new(OF_env, rtc, "compatible", "rtc,via-pmu");
#else
        OF_prop_string_new(OF_env, rtc, "compatible", "rtc");
#endif
        OF_node_put(OF_env, rtc);
    }
        //        OF_node_put(OF_env, via);
    }
    {
        OF_node_t *pmgt;
        pmgt = OF_node_new(OF_env, mio, "power-mgt", OF_ADDRESS_NONE);
        OF_prop_string_new(OF_env, pmgt, "device_type", "power-mgt");
        OF_prop_string_new(OF_env, pmgt, "compatible", "cuda");
        OF_prop_string_new(OF_env, pmgt, "mgt-kind", "min-consumption-pwm-led");
        OF_node_put(OF_env, pmgt);
    }

    if (arch == ARCH_HEATHROW) {
        /* NVRAM */
        OF_node_t *nvr;
        OF_regprop_t regs;
        nvr = OF_node_new(OF_env, mio, "nvram", 0x60000);
        OF_prop_string_new(OF_env, nvr, "device_type", "nvram");
        regs.address = 0x60000;
        regs.size = 0x00020000;
        OF_property_new(OF_env, nvr, "reg", &regs, sizeof(regs));
        OF_prop_int_new(OF_env, nvr, "#bytes", 0x2000);
        OF_node_put(OF_env, nvr);
    }

 out:
    //    OF_node_put(OF_env, mio);
    OF_node_put(OF_env, chs);
    OF_node_put(OF_env, als);
}

void OF_finalize_pci_ide (void *dev, 
                          uint32_t io_base0, uint32_t io_base1,
                          uint32_t io_base2, uint32_t io_base3)
{
    OF_env_t *OF_env = OF_env_main;
    OF_node_t *pci_ata = dev;
    OF_node_t *ata, *atas[2];
    int i;

    OF_prop_int_new(OF_env, pci_ata, "#address-cells", 1);
    OF_prop_int_new(OF_env, pci_ata, "#size-cells", 0);

    /* XXX: Darwin handles only one device */
    for(i = 0; i < 1; i++) {
        ata = OF_node_new(OF_env, pci_ata, "ata-4", i);
        if (ata == NULL) {
            ERROR("Cannot create 'ata-4'\n");
            return;
        }
        OF_prop_string_new(OF_env, ata, "device_type", "ata");
        OF_prop_string_new(OF_env, ata, "compatible", "cmd646-ata");
        OF_prop_string_new(OF_env, ata, "model", "ata-4");
        OF_prop_int_new(OF_env, ata, "#address-cells", 1);
        OF_prop_int_new(OF_env, ata, "#size-cells", 0);
        OF_prop_int_new(OF_env, ata, "reg", i);
        atas[i] = ata;
    }
    ide_pci_pc_register(io_base0, io_base1, io_base2, io_base3,
                        atas[0], atas[1]);
}

/*****************************************************************************/
/* Fake package */
static void OF_method_fake (OF_env_t *OF_env)
{
    uint32_t ihandle;

    ihandle = popd(OF_env);
    OF_DPRINTF("ih: %0x %d\n", ihandle, stackd_depth(OF_env));
    pushd(OF_env, ihandle);
}

static void OF_mmu_translate (OF_env_t *OF_env)
{
    const unsigned char *args;
    uint32_t address, more;
    uint32_t ihandle;

    OF_CHECK_NBARGS(OF_env, 4);
    /* As we get a 1:1 mapping, do nothing */
    ihandle = popd(OF_env);
    args = (void *)popd(OF_env);
    address = popd(OF_env);
    more = popd(OF_env);
    OF_DPRINTF("Translate address %0x %0x %0x\n", ihandle, address, more);
    //    BAT_setup(3, more, address, 0x10000000, 1, 1, 2);
    pushd(OF_env, address);
    pushd(OF_env, 0x00000000);
    pushd(OF_env, 0x00000000);
    pushd(OF_env, 0);
}

static void OF_mmu_map (OF_env_t *OF_env)
{
    const unsigned char *args;
    uint32_t address, virt, size;
    uint32_t ihandle;

    OF_CHECK_NBARGS(OF_env, 6);
    /* As we get a 1:1 mapping, do nothing */
    ihandle = popd(OF_env);
    args = (void *)popd(OF_env);
    popd(OF_env);
    size = popd(OF_env);
    virt = popd(OF_env);
    address = popd(OF_env);
    OF_DPRINTF("Map %0x %0x %0x %0x\n", ihandle, address,
               virt, size);
    pushd(OF_env, 0);
}

/* Serial device package */
static void OF_serial_write (OF_env_t *OF_env)
{
    const unsigned char *args;
    OF_inst_t *inst;
    OF_node_t *node;
    uint32_t ihandle;
    unsigned char *str;
    int len;

    OF_CHECK_NBARGS(OF_env, 4);
    ihandle = popd(OF_env);
    args = (void *)popd(OF_env);
    str = (void *)popd(OF_env);
    len = popd(OF_env);
    inst = OF_inst_find(OF_env, ihandle);
    if (inst == NULL) {
        pushd(OF_env, -1);
        ERROR("Cannot get serial instance\n");
        return;
    }
    node = inst->node;
    //    OF_DPRINTF("args: %p str: %p\n", args, str);
    /* XXX: should use directly the serial port
     *      and have another console package.
     */
    console_write(str, len);
    pushd(OF_env, 0);
}

static void OF_serial_read (OF_env_t *OF_env)
{
    const unsigned char *args;
    char *dest;
    uint32_t len;
    uint32_t ihandle;
    uint16_t phandle;
    int ret, count;

    OF_CHECK_NBARGS(OF_env, 4);
    ihandle = popd(OF_env);
    args = (void *)popd(OF_env);
    phandle = (ihandle >> 16) & 0xFFFF;
    dest = (void *)popd(OF_env);
    len = popd(OF_env);
    ret = -1; /* Don't know why gcc thinks it might be uninitialized... */
    for (count = 0; count < 1000; count++) {
        ret = console_read(dest, len);
        /* Stop if we read something or got an error */
        if (ret != 0)
            break;
        /* Random sleep. Seems allright for serial port */
        usleep(10000);
    }
    if (ret <= 0) {
        pushd(OF_env, 0);
    } else {
        OF_DPRINTF("send '%s'\n", dest);
        pushd(OF_env, ret);
    }
}

typedef struct blockdev_inst_t {
    int type;
    union {
        bloc_device_t *bd;
        part_t *part;
        inode_t *file;
    } u;
} blockdev_inst_t;

static int OF_split_args (unsigned char *args, unsigned char **argv,
                          int max_args)
{
    unsigned char *pos, *end;
    int i;

    pos = args;
    end = pos;
    for (i = 0; i < max_args && *pos != '\0' && end != NULL; i++) {
        end = strchr(pos, ',');
        if (end != NULL)
            *end = '\0';
        argv[i] = pos;
        pos = end + 1;
    }

    return i;
}

static void OF_convert_path (unsigned char **path)
{
    unsigned char *pos;

    OF_DPRINTF("%s: '%s'\n", __func__, *path);
    for (pos = *path; *pos != '\0'; pos++) {
        if (*pos == '\\')
            *pos = '/';
    }
    OF_DPRINTF("%s: '%s'\n", __func__, *path);
    pos = *path;
#if 1
    if (pos[0] == '/' && pos[1] == '/') {
        pos += 2;
        *path = pos;
    }
#else
    for (; *pos == '/'; pos++)
        continue;
    *path = pos;
#endif
    OF_DPRINTF("%s: '%s'\n", __func__, *path);
}

/* Block devices package */
static void OF_blockdev_open (OF_env_t *OF_env)
{
    unsigned char tmp[OF_NAMELEN_MAX];
    unsigned char *args, *argv[4];
    OF_inst_t *dsk_inst;
    OF_node_t *dsk;
    bloc_device_t *bd;
    blockdev_inst_t *bdinst;
    uint32_t ihandle;
    uint16_t phandle;
    int nargs, partnum;

    OF_CHECK_NBARGS(OF_env, 2);
    ihandle = popd(OF_env);
    args = (void *)popd(OF_env);
    phandle = (ihandle >> 16) & 0xFFFF;
    dsk_inst = OF_inst_find(OF_env, ihandle);
    if (dsk_inst == NULL) {
        ERROR("Disk not found (ih: %0x)\n", ihandle);
        pushd(OF_env, -1);
        return;
    }
    dsk = dsk_inst->node;
    bd = dsk->private_data;
    bdinst = malloc(sizeof(blockdev_inst_t));
    if (bdinst == NULL) {
        ihandle = -1;
        ERROR("Cannot alloc blockdev instance\n");
        goto out;
    }
    memset(bdinst, 0, sizeof(blockdev_inst_t));
    OF_DPRINTF("called with args '%s'\n", args);
    nargs = OF_split_args(args, argv, 4);
    partnum = -1;
    if (nargs > 0) {
        partnum = strtol(argv[0], NULL, 10);
        if (partnum > 0) {
            OF_DPRINTF("Open partition... %d %d\n", partnum, nargs);
            bdinst->type = 1;
            bdinst->u.part = part_get(bd, partnum);
            if (bdinst->u.part == NULL) {
                OF_DPRINTF("Partition %d not found\n", partnum);
                free(bdinst);
                pushd(OF_env, -1);
                return;
            }
            if (nargs > 1) {
                /* TODO: open file */
                bdinst->type = 2;
                OF_DPRINTF("Open file... %d %d '%s'\n",
                           partnum, nargs, argv[1]);
                OF_convert_path(&argv[1]);
                if (*argv[1] != '/') {
                    sprintf(tmp, "%s/%s",
                            fs_get_boot_dirname(part_fs(bdinst->u.part)),
                            argv[1]);
                    bdinst->u.file = fs_open(part_fs(bdinst->u.part), tmp);
                } else {
                    bdinst->u.file = fs_open(part_fs(bdinst->u.part), argv[1]);
                }
                if (bdinst->u.file == NULL) {
#if 0
                    bug();
#endif
                    pushd(OF_env, 0x00000000);
                    ERROR("File not found '%s'\n", argv[1]);
                    return;
                }
            }
        }
    }
    if (nargs == 0 || partnum == 0) {
        OF_DPRINTF("Open disk... %d %d\n", nargs, partnum);
        bdinst->type = 0;
        bdinst->u.bd = bd;
    }
    /* TODO: find partition &/| file */
    dsk_inst->data = bdinst;
    OF_node_put(OF_env, dsk);
 out:
    pushd(OF_env, ihandle);
}

static void OF_blockdev_seek (OF_env_t *OF_env)
{
    const unsigned char *args;
    OF_inst_t *dsk_inst;
    blockdev_inst_t *bdinst;
    uint32_t posh, posl, bloc, pos, blocsize, tmp;
    uint32_t ihandle;
    uint16_t phandle;
    int sh;

    OF_CHECK_NBARGS(OF_env, 4);
    ihandle = popd(OF_env);
    args = (void *)popd(OF_env);
    phandle = (ihandle >> 16) & 0xFFFF;
    posh = popd(OF_env);
    posl = popd(OF_env);
    dsk_inst = OF_inst_find(OF_env, ihandle);
    if (dsk_inst == NULL) {
        ERROR("Disk not found (ih: %0x)\n", ihandle);
        pushd(OF_env, -1);
        return;
    }
    bdinst = dsk_inst->data;
    switch (bdinst->type) {
    case 0:
        blocsize = bd_seclen(bdinst->u.bd);
        for (tmp = blocsize, sh = 0; tmp != 1; tmp = tmp / 2)
            sh++;
        bloc = ((posh  << (32 - sh)) | (posl / blocsize));
        pos = posl % blocsize;
        OF_DPRINTF("disk: bsize %08x %08x %08x => %08x %08x\n", blocsize,
               posh, posl, bloc, pos);
        pushd(OF_env, bd_seek(bdinst->u.bd, bloc, pos));
        break;
    case 1:
        blocsize = part_blocsize(bdinst->u.part);
        for (tmp = blocsize, sh = 0; tmp != 1; tmp = tmp / 2)
            sh++;
        bloc = ((posh  << (32 - sh)) | (posl / blocsize));
        pos = posl % blocsize;
        OF_DPRINTF("part: bsize %08x %08x %08x => %08x %08x\n", blocsize,
               posh, posl, bloc, pos);
        pushd(OF_env, part_seek(bdinst->u.part, bloc, pos));
        break;
    case 2:
        blocsize = part_blocsize(fs_inode_get_part(bdinst->u.file));
        for (tmp = blocsize, sh = 0; tmp != 1; tmp = tmp / 2)
            sh++;
        bloc = ((posh  << (32 - sh)) | (posl / blocsize));
        pos = posl % blocsize;
        OF_DPRINTF("file: bsize %08x %08x %08x => %08x %08x\n", blocsize,
                   posh, posl, bloc, pos);
        pushd(OF_env, fs_seek(bdinst->u.file, bloc, pos));
        break;
    }
}

static void OF_blockdev_read (OF_env_t *OF_env)
{
    const unsigned char *args;
    OF_inst_t *dsk_inst;
    blockdev_inst_t *bdinst;
    void *dest;
    uint32_t len;
    uint32_t ihandle;
    uint16_t phandle;

    OF_CHECK_NBARGS(OF_env, 4);
    ihandle = popd(OF_env);
    args = (void *)popd(OF_env);
    phandle = (ihandle >> 16) & 0xFFFF;
    dest = (void *)popd(OF_env);
    len = popd(OF_env);
    dsk_inst = OF_inst_find(OF_env, ihandle);
    if (dsk_inst == NULL) {
        ERROR("Disk not found (ih: %0x)\n", ihandle);
        pushd(OF_env, -1);
        return;
    }
    bdinst = dsk_inst->data;
    set_check(0);
    OF_DPRINTF("dest: %p len: %d %d\n", dest, len, bdinst->type);
    switch (bdinst->type) {
    case 0:
        OF_DPRINTF("read disk\n");
        pushd(OF_env, bd_read(bdinst->u.bd, dest, len));
        break;
    case 1:
        OF_DPRINTF("read partition\n");
        pushd(OF_env, part_read(bdinst->u.part, dest, len));
        break;
    case 2:
        OF_DPRINTF("read file\n");
        pushd(OF_env, fs_read(bdinst->u.file, dest, len));
        break;
    }
    OF_DPRINTF("%08x %08x %08x %08x\n",
               ((uint32_t *)dest)[0], ((uint32_t *)dest)[1],
               ((uint32_t *)dest)[2], ((uint32_t *)dest)[3]);
    OF_DPRINTF("%08x %08x %08x %08x\n",
               ((uint32_t *)dest)[4], ((uint32_t *)dest)[5],
               ((uint32_t *)dest)[6], ((uint32_t *)dest)[7]);
        
    set_check(1);
}

static void OF_blockdev_get_blocsize (OF_env_t *OF_env)
{
    const unsigned char *args;
    OF_inst_t *dsk_inst;
    blockdev_inst_t *bdinst;
    uint32_t ihandle;
    uint16_t phandle;
    uint32_t blocsize;

    OF_CHECK_NBARGS(OF_env, 2);
    ihandle = popd(OF_env);
    args = (void *)popd(OF_env);
    phandle = (ihandle >> 16) & 0xFFFF;
    dsk_inst = OF_inst_find(OF_env, ihandle);
    if (dsk_inst == NULL) {
        ERROR("Disk not found (ih: %0x)\n", ihandle);
        pushd(OF_env, -1);
        return;
    }
    bdinst = dsk_inst->data;
#if 0
    switch (bdinst->type) {
    case 0:
        blocsize = bd_seclen(bdinst->u.bd);
        break;
    case 1:
        blocsize = part_blocsize(bdinst->u.part);
        break;
    case 2:
        blocsize = 512;
        break;
    }
#else
    blocsize = 512;
#endif
    pushd(OF_env, blocsize);
    pushd(OF_env, 0);
}

static void OF_blockdev_dma_alloc (OF_env_t *OF_env)
{
    const unsigned char *args;
    void *address;
    uint32_t ihandle;
    uint32_t size;

    OF_CHECK_NBARGS(OF_env, 3);
    ihandle = popd(OF_env);
    args = (void *)popd(OF_env);
    size = popd(OF_env);
    OF_DPRINTF("size: %08x\n", size);
    mem_align(size);
    address = malloc(size);
    if (address != NULL)
        memset(address, 0, size);
    pushd(OF_env, (uint32_t)address);
    pushd(OF_env, 0);
}

static void OF_blockdev_dma_free (OF_env_t *OF_env)
{
    const unsigned char *args;
    void *address;
    uint32_t ihandle;
    uint32_t size;

    OF_CHECK_NBARGS(OF_env, 4);
    ihandle = popd(OF_env);
    args = (void *)popd(OF_env);
    size = popd(OF_env);
    address = (void *)popd(OF_env);
    OF_DPRINTF("address: %p size: %08x\n", address, size);
    free(address);
    pushd(OF_env, 0);
}

void *OF_blockdev_register (void *parent, void *private,
                            const unsigned char *type,
                            const unsigned char *name, int devnum,
                            const char *alias)
{
    unsigned char tmp[OF_NAMELEN_MAX], path[OF_NAMELEN_MAX], *pos;
    OF_env_t *OF_env;
    OF_node_t *dsk, *als;
    int i;
    
    OF_env = OF_env_main;
    dsk = OF_node_new(OF_env, parent, name, devnum);
    if (dsk == NULL) {
        ERROR("Cannot create blockdev '%s'\n", name);
        return NULL;
    }
    OF_prop_string_new(OF_env, dsk, "device_type", "block");
    OF_prop_string_new(OF_env, dsk, "category", type);
    OF_prop_int_new(OF_env, dsk, "device_id", devnum);
    OF_prop_int_new(OF_env, dsk, "reg", devnum);
    OF_method_new(OF_env, dsk, "open", &OF_blockdev_open);
    OF_method_new(OF_env, dsk, "seek", &OF_blockdev_seek);
    OF_method_new(OF_env, dsk, "read", &OF_blockdev_read);
    OF_method_new(OF_env, dsk, "block-size",
                  &OF_blockdev_get_blocsize);
    OF_method_new(OF_env, dsk, "dma-alloc", &OF_blockdev_dma_alloc);
    OF_method_new(OF_env, dsk, "dma-free", &OF_blockdev_dma_free);
    if (strcmp(type, "cdrom") == 0)
        OF_method_new(OF_env, dsk, "eject", &OF_method_fake);
    OF_method_new(OF_env, dsk, "close", &OF_method_fake);
    dsk->private_data = private;
    /* Set up aliases */
    OF_pack_get_path(OF_env, path, OF_NAMELEN_MAX, dsk);
    if (alias != NULL) {
        als = OF_node_get(OF_env, "aliases");
        if (als == NULL) {
            ERROR("Cannot get 'aliases'\n");
            return NULL;
        }
        strcpy(tmp, alias);
        if (OF_property_copy(OF_env, NULL, 0, als, tmp) >= 0) {
            pos = tmp + strlen(alias);
            for (i = 0; ; i++) {
                sprintf(pos, "%d", i);
                if (OF_property_copy(OF_env, NULL, 0, als, tmp) < 0)
                    break;
            }
        }
        OF_DPRINTF("Set alias to %s\n", tmp);
        OF_prop_string_new(OF_env, dsk, "alias", tmp);
        OF_prop_string_new(OF_env, als, tmp, path);
        OF_node_put(OF_env, als);
    }
    
    return dsk;
}

void OF_blockdev_set_boot_device (void *disk, int partnum,
                                  const unsigned char *file)
{
    unsigned char tmp[OF_NAMELEN_MAX], *pos;
    OF_env_t *OF_env;
    OF_node_t *dsk = disk, *opts, *chs;
    
    OF_env = OF_env_main;
    
    if (OF_property_copy(OF_env, tmp, OF_NAMELEN_MAX, dsk, "alias") < 0)
        OF_pack_get_path(OF_env, tmp, OF_NAMELEN_MAX, dsk);
    sprintf(tmp + strlen(tmp), ":%d", partnum);
    /* OpenDarwin 6.02 seems to need this one */
    opts = OF_node_get(OF_env, "options");
    if (opts == NULL) {
        ERROR("Cannot get 'options'\n");
        return;
    }
    OF_prop_string_set(OF_env, OF_node_root, "boot-device", tmp);
    OF_prop_string_set(OF_env, opts, "boot-device", tmp);
    OF_DPRINTF("Set boot device to: '%s'\n", tmp);
    OF_node_put(OF_env, opts);
    /* Set the real boot path */
    pos = tmp + strlen(tmp);
    sprintf(pos, ",%s", file);
    /* Convert all '/' into '\' in the boot file name */
    for (; *pos != '\0'; pos++) {
        if (*pos == '/')
            *pos = '\\';
    }
    chs = OF_node_get(OF_env, "chosen");
    if (chs == NULL) {
        ERROR("Cannot get 'chosen'\n");
        return;
    }
    OF_prop_string_set(OF_env, chs, "bootpath", tmp);
    OF_DPRINTF("Set boot path to: '%s'\n", tmp);
    OF_node_put(OF_env, chs);
}

/* Display package */
static void OF_vga_draw_rectangle (OF_env_t *OF_env)
{
    const void *buf;
    const unsigned char *args;
    uint32_t posx, posy, width, height;
    uint32_t ihandle;

    OF_CHECK_NBARGS(OF_env, 7);
    ihandle = popd(OF_env);
    args = (void *)popd(OF_env);
    height = popd(OF_env);
    width = popd(OF_env);
    posy = popd(OF_env);
    posx = popd(OF_env);
    buf = (const void *)popd(OF_env);
    OF_DPRINTF("x=%d y=%d h=%d ", posx, posy, width);
    OF_DPRINTF("w=%d buf=%p\n", height, buf);
    set_check(0);
    vga_draw_buf(buf, width * vga_fb_bpp, posx, posy, width, height);
    set_check(1);
    pushd(OF_env, 0);
}

static void OF_vga_fill_rectangle (OF_env_t *OF_env)
{
    const unsigned char *args;
    uint32_t color, posx, posy, width, height;
    uint32_t ihandle;

    OF_CHECK_NBARGS(OF_env, 7);
    ihandle = popd(OF_env);
    args = (void *)popd(OF_env);
    height = popd(OF_env);
    width = popd(OF_env);
    posy = popd(OF_env);
    posx = popd(OF_env);
    color = popd(OF_env);
    OF_DPRINTF("x=%d y=%d\n", posx, posy);
    OF_DPRINTF("h=%d w=%d c=%0x\n", width, height, color);
    vga_fill_rect(posx, posy, width, height, color);
    pushd(OF_env, 0);
}

static void OF_vga_set_width (OF_env_t *OF_env, OF_prop_t *prop,
                              const void *data, int len)
{
    uint32_t width, height, depth;

    if (len == sizeof(uint32_t)) {
        width = *(uint32_t *)data;
        OF_property_copy(OF_env, &height, 4, prop->node, "height");
        OF_property_copy(OF_env, &depth, 4, prop->node, "depth");
        vga_set_mode(width, height, depth);
    }
}

static void OF_vga_set_height (OF_env_t *OF_env, OF_prop_t *prop,
                               const void *data, int len)
{
    uint32_t width, height, depth;

    if (len == sizeof(uint32_t)) {
        OF_property_copy(OF_env, &width, 4, prop->node, "width");
        height = *(uint32_t *)data;
        OF_property_copy(OF_env, &depth, 4, prop->node, "depth");
        vga_set_mode(width, height, depth);
    }
}

static void OF_vga_set_depth (OF_env_t *OF_env, OF_prop_t *prop,
                              const void *data, int len)
{
    uint32_t width, height, depth;

    if (len == sizeof(uint32_t)) {
        OF_property_copy(OF_env, &width, 4, prop->node, "width");
        OF_property_copy(OF_env, &height, 4, prop->node, "height");
        depth = *(uint32_t *)data;
        vga_set_mode(width, height, depth);
    }
}

void OF_vga_register (const unsigned char *name, unused uint32_t address,
                      int width, int height, int depth,
                      unsigned long vga_bios_addr, unsigned long vga_bios_size)
{
    OF_env_t *OF_env;
    unsigned char tmp[OF_NAMELEN_MAX];
    OF_node_t *disp, *chs, *als;
    OF_prop_t *prop;
    
    OF_DPRINTF("Set frame buffer %08x %dx%dx%d\n",
               address, width, height, depth);
    OF_env = OF_env_main;
    disp = OF_node_get(OF_env, name);
    if (disp == NULL) {
        ERROR("Cannot get display '%s'\n", name);
        return;
    }
    prop = OF_prop_int_new(OF_env, disp, "width", width);
    if (prop == NULL) {
        OF_node_put(OF_env, disp);
        ERROR("Cannot create display width property\n");
        return;
    }
    OF_property_set_cb(OF_env, prop, &OF_vga_set_width);
    prop = OF_prop_int_new(OF_env, disp, "height", height);
    if (prop == NULL) {
        OF_node_put(OF_env, disp);
        ERROR("Cannot create display height property\n");
        return;
    }
    OF_property_set_cb(OF_env, prop, &OF_vga_set_height);
    switch (depth) {
    case 8:
        break;
    case 15:
        depth = 16;
        break;
    case 32:
        break;
    default:
        /* OF spec this is mandatory, but we have no support for it */
        printf("%d bits VGA isn't implemented\n", depth);
        bug();
        /* Never come here */
        break;
    }
    prop = OF_prop_int_new(OF_env, disp, "depth", depth);
    if (prop == NULL) {
        ERROR("Cannot create display depth\n");
        goto out;
    }
    OF_property_set_cb(OF_env, prop, &OF_vga_set_depth);
    OF_prop_int_new(OF_env, disp, "linebytes", vga_fb_linesize);
    OF_method_new(OF_env, disp, "draw-rectangle", &OF_vga_draw_rectangle);
    OF_method_new(OF_env, disp, "fill-rectangle", &OF_vga_fill_rectangle);
    OF_method_new(OF_env, disp, "color!", &OF_method_fake);
    chs = OF_node_get(OF_env, "chosen");
    if (chs == NULL) {
        ERROR("Cannot get 'chosen'\n");
        goto out;
    }
    OF_prop_int_new(OF_env, chs, "display", OF_pack_handle(OF_env, disp));
    OF_node_put(OF_env, chs);
    OF_pack_get_path(OF_env, tmp, 512, disp);
    printf("Set display '%s' path to '%s'\n", name, tmp);
    als = OF_node_get(OF_env, "aliases");
    if (als == NULL) {
        ERROR("Cannot get 'aliases'\n");
        goto out;
    }
    OF_prop_string_new(OF_env, als, "screen", tmp);
    OF_prop_string_new(OF_env, als, "display", tmp);
    OF_node_put(OF_env, als);
    /* XXX: may also need read-rectangle */

    if (vga_bios_size >= 8) {
        const uint8_t *p;
        int size;
        /* check the QEMU VGA BIOS header */
        p = (const uint8_t *)vga_bios_addr;
        if (p[0] == 'N' && p[1] == 'D' && p[2] == 'R' && p[3] == 'V') {
            size = *(uint32_t *)(p + 4);
            OF_property_new(OF_env, disp, "driver,AAPL,MacOS,PowerPC", 
                            p + 8, size);
        }
    }
 out:
    OF_node_put(OF_env, disp);
}

/* Pseudo packages to make BootX happy */
/* sl_words package */
static void slw_set_output_level (OF_env_t *OF_env)
{
    OF_node_t *slw;
    const unsigned char *args;
    int level;

    OF_CHECK_NBARGS(OF_env, 3);
    popd(OF_env);
    args = (void *)popd(OF_env);
    level = popd(OF_env);
    slw = OF_node_get(OF_env, "sl_words");
    if (slw == NULL) {
        pushd(OF_env, -1);
    } else {
        OF_DPRINTF("Set output level to: %d\n", level);
        OF_prop_int_set(OF_env, slw, "outputLevel", level);
        OF_node_put(OF_env, slw);
        pushd(OF_env, 0);
    }
}

#ifdef DEBUG_BIOS
#define EMIT_BUFFER_LEN 256
static unsigned char emit_buffer[EMIT_BUFFER_LEN];
static int emit_pos = 0;
#endif

static void slw_emit (OF_env_t *OF_env)
{
    const unsigned char *args;
    int c;

    OF_CHECK_NBARGS(OF_env, 3);
    popd(OF_env);
    args = (void *)popd(OF_env);
    c = popd(OF_env);
    //    OF_DPRINTF("Emit char %d\n", c);
#ifdef DEBUG_BIOS
    if (emit_pos < EMIT_BUFFER_LEN - 1) {
        emit_buffer[emit_pos++] = c;
        //        outb(0xFF00, c);
        outb(0x0F00, c);
    } else {
        emit_buffer[emit_pos] = '\0';
    }
#else
    outb(0x0F00, c);
#endif
    pushd(OF_env, 0);
}

static void slw_cr (OF_env_t *OF_env)
{
    const unsigned char *args;

    OF_CHECK_NBARGS(OF_env, 2);
    popd(OF_env);
    args = (void *)popd(OF_env);
    //    OF_DPRINTF("Emit CR char\n");
    //    outb(0xFF01, '\n');
    outb(0x0F01, '\n');
#ifdef DEBUG_BIOS
    emit_buffer[emit_pos] = '\0';
    if (strcmp(emit_buffer, "Call Kernel!") == 0) {
        /* Set qemu in debug mode:
         * log in_asm,op,int,ioport,cpu
         */
        uint16_t loglevel = 0x02 | 0x10 | 0x80;
        //        outw(0xFF02, loglevel);
        outb(0x0F02, loglevel);
    }
    emit_pos = 0;
#endif
    pushd(OF_env, 0);
}

static void slw_init_keymap (OF_env_t *OF_env)
{
    const unsigned char *args;
    OF_node_t *node;
    OF_prop_t *prop;
    uint32_t phandle, ihandle;

    OF_CHECK_NBARGS(OF_env, 3);
    ihandle = popd(OF_env);
    args = (void *)popd(OF_env);
    phandle = ihandle >> 16;
    ihandle &= 0xFFFF;
    OF_DPRINTF("\n");
    node = OF_pack_find(OF_env, phandle);
    if (node == NULL) {
        ERROR("Cant' init slw keymap\n");
        pushd(OF_env, -1);
    } else {
        prop = OF_property_get(OF_env, node, "keyMap");
        if (prop == NULL) {
            pushd(OF_env, -1);
        } else {
            pushd(OF_env, (uint32_t)prop->value);
            pushd(OF_env, 0);
        }
    }
}

static void slw_update_keymap (OF_env_t *OF_env)
{
    const unsigned char *args;

    OF_CHECK_NBARGS(OF_env, 2);
    popd(OF_env);
    args = (void *)popd(OF_env);
    OF_DPRINTF("\n");
    pushd(OF_env, 0);
}

static void slw_spin (OF_env_t *OF_env)
{
    const unsigned char *args;
    /* XXX: cur_spin should be in sl_words package */
    static int cur_spin = 0;
    int c;

    OF_CHECK_NBARGS(OF_env, 2);
    popd(OF_env);
    args = (void *)popd(OF_env);
    if (cur_spin > 15) {
        c = RGB(0x30, 0x30, 0x50);
    } else {
        c = RGB(0x11, 0x11, 0x11);
    }
    c = vga_get_color(c);
    vga_fill_rect((cur_spin % 15) * 5 + 280, 420, 4, 3, c);
    cur_spin = (cur_spin + 1) & 31;
    OF_DPRINTF("\n");
    pushd(OF_env, -1);
}

static void slw_spin_init (OF_env_t *OF_env)
{
    const unsigned char *args;

    OF_CHECK_NBARGS(OF_env, 8);
    popd(OF_env);
    args = (void *)popd(OF_env);
    popd(OF_env);
    popd(OF_env);
    popd(OF_env);
    popd(OF_env);
    popd(OF_env);
    popd(OF_env);
    pushd(OF_env, -1);
}

static void slw_pwd (OF_env_t *OF_env)
{
    const unsigned char *args;

    OF_CHECK_NBARGS(OF_env, 3);
    popd(OF_env);
    args = (void *)popd(OF_env);
    OF_DPRINTF("\n");
    pushd(OF_env, -1);
}

static void slw_sum (OF_env_t *OF_env)
{
    const unsigned char *args;

    OF_CHECK_NBARGS(OF_env, 3);
    popd(OF_env);
    args = (void *)popd(OF_env);
    OF_DPRINTF("\n");
    pushd(OF_env, -1);
}

/*****************************************************************************/
/*                       Client program interface                            */
/* Client interface services */
static void OF_test (OF_env_t *OF_env);

/* Device tree services */
/* Get next package */
__attribute__ (( section (".OpenFirmware") ))
static void OF_peer (OF_env_t *OF_env)
{
    OF_node_t *node;
    uint32_t phandle;

    OF_CHECK_NBARGS(OF_env, 1);
    phandle = popd(OF_env);
    OF_DPRINTF("phandle 0x%0x\n", phandle);
    if (phandle == 0)
        node = OF_node_root;
    else
        node = OF_pack_next(OF_env, phandle);
    if (node == NULL)
        pushd(OF_env, 0);
    else
        pushd(OF_env, OF_pack_handle(OF_env, node));
}

/* Get first child package */
__attribute__ (( section (".OpenFirmware") ))
static void OF_child (OF_env_t *OF_env)
{
    OF_node_t *node;
    uint32_t phandle;

    OF_CHECK_NBARGS(OF_env, 1);
    phandle = popd(OF_env);
    OF_DPRINTF("phandle 0x%0x\n", phandle);
    node = OF_pack_child(OF_env, phandle);
    if (node == NULL)
        pushd(OF_env, 0);
    else
        pushd(OF_env, OF_pack_handle(OF_env, node));
}

/* Get parent package */
__attribute__ (( section (".OpenFirmware") ))
static void OF_parent (OF_env_t *OF_env)
{
    OF_node_t *node;
    uint32_t phandle;

    OF_CHECK_NBARGS(OF_env, 1);
    phandle = popd(OF_env);
    OF_DPRINTF("phandle 0x%0x\n", phandle);
    node = OF_pack_parent(OF_env, phandle);
    if (node == NULL)
        pushd(OF_env, 0);
    else
        pushd(OF_env, OF_pack_handle(OF_env, node));
}

/* Get package related to an instance */
__attribute__ (( section (".OpenFirmware") ))
static void OF_instance_to_package (OF_env_t *OF_env)
{
    uint32_t ihandle;

    OF_CHECK_NBARGS(OF_env, 1);
    ihandle = popd(OF_env);
    OF_DPRINTF("ihandle 0x%0x\n", ihandle);
    pushd(OF_env, (ihandle >> 16) & 0xFFFF);
}

/* Get property len */
__attribute__ (( section (".OpenFirmware") ))
static void OF_getproplen (OF_env_t *OF_env)
{
    unsigned char name[OF_NAMELEN_MAX], *namep;
    OF_node_t *node;
    uint32_t phandle;

    OF_CHECK_NBARGS(OF_env, 2);
    phandle = popd(OF_env);
    namep = (unsigned char *)popd(OF_env);
    OF_lds(name, namep);
    OF_DPRINTF("phandle 0x%0x prop [%s]\n", phandle, name);
    node = OF_pack_find(OF_env, phandle);
    if (node == NULL)
        pushd(OF_env, -1);
    else
        pushd(OF_env, OF_property_len(OF_env, node, name));
}

/* Get property */
__attribute__ (( section (".OpenFirmware") ))
static void OF_getprop (OF_env_t *OF_env)
{
    unsigned char name[OF_NAMELEN_MAX], *namep;
    OF_node_t *node;
    void *buffer;
    uint32_t phandle;
    int len, nb_args;

    //    OF_CHECK_NBARGS(OF_env, 4);
    nb_args = stackd_depth(OF_env);
    phandle = popd(OF_env);
    namep = (unsigned char *)popd(OF_env);
    OF_lds(name, namep);
    buffer = (void *)popd(OF_env);
    if (nb_args == 3) {
        /* This hack is needed to boot MacOS X panther (10.3) */
        len = 1024;
    } else {
        len = popd(OF_env);
    }
    OF_DPRINTF("phandle 0x%0x prop [%s]\n", phandle, name);
    OF_DPRINTF("buffer %p len %d\n", buffer, len);
    node = OF_pack_find(OF_env, phandle);
    if (node == NULL) {
        len = -1;
    } else {
        len = OF_property_copy(OF_env, buffer, len, node, name);
        if (len != -1) {
            OF_DPRINTF("Copied %d bytes\n", len);
        }
    }
    pushd(OF_env, len);
}

/* Check existence of next property */
__attribute__ (( section (".OpenFirmware") ))
static void OF_nextprop (OF_env_t *OF_env)
{
    unsigned char name[OF_NAMELEN_MAX], *namep;
    OF_node_t *node;
    OF_prop_t *next;
    unsigned char *next_name;
    uint32_t phandle;

    OF_CHECK_NBARGS(OF_env, 3);
    phandle = popd(OF_env);
    namep = (unsigned char *)popd(OF_env);
    OF_lds(name, namep);
    OF_DPRINTF("phandle 0x%0x prop [%s]\n", phandle, name);
    next_name = (unsigned char *)popd(OF_env);
    node = OF_pack_find(OF_env, phandle);
    if (node == NULL) {
        pushd(OF_env, -1);
    } else {
        next = OF_property_next(OF_env, node, name);
        if (next == NULL || next->name == NULL) {
            OF_DPRINTF("No next property found [%s]\n", name);
            pushd(OF_env, 0);
        } else {
            OF_DPRINTF("Return property name [%s]\n", next->name);
            OF_sts(next_name, (void *)(next->name));
            OF_DUMP_STRING(OF_env, next_name);
            pushd(OF_env, strlen(next->name) + 1);
        }
    }
}

/* Set a property */
__attribute__ (( section (".OpenFirmware") ))
static void OF_setprop (OF_env_t *OF_env)
{
    unsigned char name[OF_NAMELEN_MAX], *namep;
    unsigned char *value, *buffer;
    OF_node_t *node;
    OF_prop_t *prop;
    uint32_t phandle;
    int len;
    int i;

    OF_CHECK_NBARGS(OF_env, 4);
    phandle = popd(OF_env);
    namep = (unsigned char *)popd(OF_env);
    OF_lds(name, namep);
    OF_DPRINTF("phandle 0x%0x prop [%s]\n", phandle, name);
    buffer = (unsigned char *)popd(OF_env);
    len = popd(OF_env);
    node = OF_pack_find(OF_env, phandle);
    if (node == NULL) {
        pushd(OF_env, -1);
        ERROR("Cannot get pack %04x\n", phandle);
        return;
    }
    value = malloc(len);
    if (value == NULL && len != 0) {
        pushd(OF_env, -1);
        ERROR("%s: Cannot alloc property '%s' (%d)\n", __func__, name, len);
        return;
    }
    for (i = 0; i < len; i++)
        value[i] = buffer[i];
    prop = OF_property_set(OF_env, node, name, value, len);
    if (prop == NULL)
        len = -1;
   pushd(OF_env, len);
}

/* "canon" */

/* Find a device given its path */
__attribute__ (( section (".OpenFirmware") ))
static OF_node_t *OF_get_alias (OF_env_t *OF_env, const unsigned char *name)
{
    unsigned char tmp[OF_NAMELEN_MAX], *pos, *st;
    const unsigned char *alias, *npos;
    OF_node_t *als, *node;
    OF_prop_t *prop;

    node = NULL;
    strcpy(tmp, name);
    for (st = tmp; *st == '/'; st++)
        continue;
    pos = strchr(st, '/');
    if (pos == NULL) {
        pos = strchr(st, ':');
    }
    if (pos != NULL) {
        *pos = '\0';
        npos = name + (pos - tmp);
    } else {
        npos = "";
    }
    OF_DPRINTF("Look for alias for '%s' => '%s' '%s'\n", name, tmp, npos);
    als = OF_pack_find_by_name(OF_env, OF_node_root, "/aliases");
    if (als == NULL) {
        ERROR("Cannot get 'aliases'\n");
        return NULL;
    }
    prop = OF_property_get(OF_env, als, tmp);
    if (prop == NULL) {
        OF_DPRINTF("No %s alias !\n", tmp);
        goto out;
    }
    alias = prop->value;
    OF_DPRINTF("Found alias '%s' '%s'\n", alias, npos);
    sprintf(tmp, "%s%s", alias, npos);
    node = OF_pack_find_by_name(OF_env, OF_node_root, tmp);
    if (node == NULL) {
        printf("%s alias is a broken link !\n", name);
        goto out;
    }
    OF_node_put(OF_env, node);
 out:
    OF_node_put(OF_env, als);

    return node;
}

__attribute__ (( section (".OpenFirmware") ))
static void OF_finddevice (OF_env_t *OF_env)
{
    unsigned char name[OF_NAMELEN_MAX], *namep;
    OF_node_t *node;
    int ret;

    OF_CHECK_NBARGS(OF_env, 1);
    namep = (unsigned char *)popd(OF_env);
    OF_lds(name, namep);
    OF_DPRINTF("name %p [%s]\n", namep, name);
    /* Search first in "/aliases" */
    node = OF_get_alias(OF_env, name);
    if (node == NULL) {
        node = OF_pack_find_by_name(OF_env, OF_node_root, name);
    }
    if (node == NULL)
        ret = -1;
    else
        ret = OF_pack_handle(OF_env, node);
    OF_DPRINTF("ret 0x%0x\n", ret);
    pushd(OF_env, ret);
}

/* "instance-to-path */
__attribute__ (( section (".OpenFirmware") ))
static void OF_instance_to_path (OF_env_t *OF_env)
{
    void *buffer;
    OF_inst_t *inst;
    uint32_t ihandle;
    int len;

    OF_CHECK_NBARGS(OF_env, 3);
    OF_DPRINTF("\n");
    ihandle = popd(OF_env);
    buffer = (void *)popd(OF_env);
    len = popd(OF_env);
    OF_DPRINTF("ihandle: 0x%0x len=%d\n", ihandle, len);
    inst = OF_inst_find(OF_env, ihandle);
    if (inst == NULL)
        len = -1;
    else
        len = OF_inst_get_path(OF_env, buffer, len, inst) + 1;
    OF_DUMP_STRING(OF_env, buffer);
    pushd(OF_env, len);
}

/* "package-to-path" */
__attribute__ (( section (".OpenFirmware") ))
static void OF_package_to_path (OF_env_t *OF_env)
{
    void *buffer;
    OF_node_t *node;
    uint32_t phandle;
    int len;

    OF_CHECK_NBARGS(OF_env, 3);
    OF_DPRINTF("\n");
    phandle = popd(OF_env);
    buffer = (void *)popd(OF_env);
    len = popd(OF_env);
    node = OF_pack_find(OF_env, phandle);
    if (node == NULL)
        len = -1;
    else
        len = OF_pack_get_path(OF_env, buffer, len, node) + 1;
    OF_DUMP_STRING(OF_env, buffer);
    pushd(OF_env, len);
}

/* Call a package's method */
__attribute__ (( section (".OpenFirmware") ))
static void _OF_callmethod (OF_env_t *OF_env, const unsigned char *name,
                            uint32_t ihandle, const unsigned char *argp)
{
    OF_node_t *node;
    OF_inst_t *inst;
    OF_method_t *method;
    OF_cb_t cb;

    inst = OF_inst_find(OF_env, ihandle);
    OF_DPRINTF("Attempt to call method [%s] of package instance 0x%0x\n",
               name, ihandle);
    if (inst == NULL) {
        OF_DPRINTF("No instance %0x\n", ihandle);
        pushd(OF_env, -1);
        return;
    }
    node = inst->node;
    method = OF_method_get(OF_env, node, name);
    if (method != NULL) {
        cb = method->func;
    } else {
        if (strcmp(name, "open") == 0) {
            cb = &OF_method_fake;
        } else {
            printf("Method '%s' not found in '%s'\n",
                   name, node->prop_name->value);
            pushd(OF_env, -1);
            bug();
            return;
        }
    }
#if 0
    OF_DPRINTF("Push instance method %p (%p)...\n", &method->func,
               &slw_emit);
#endif
    pushf(OF_env, &cb);
    if (argp != NULL)
        pushd(OF_env, (uint32_t)argp);
    else
        pushd(OF_env, 0x00000000);
    pushd(OF_env, ihandle);
}

__attribute__ (( section (".OpenFirmware") ))
static unsigned char *OF_get_args (unused OF_env_t *env, unsigned char *name)
{
    unsigned char *sd;

    sd = strchr(name, ':');
    if (sd == NULL)
        return NULL;
    *sd = '\0';

    return sd + 1;
}

__attribute__ (( section (".OpenFirmware") ))
static void OF_callmethod (OF_env_t *OF_env)
{
    const unsigned char *args;
    unsigned char name[OF_NAMELEN_MAX], *namep;
    uint32_t ihandle;

    OF_DPRINTF("\n\n\n#### CALL METHOD ####\n\n");
    namep = (unsigned char *)popd(OF_env);
    OF_lds(name, namep);
    args = OF_get_args(OF_env, name);
    ihandle = popd(OF_env);
    _OF_callmethod(OF_env, name, ihandle, args);
}

/* Device IO services */
/* Create a new instance of a device's package */
__attribute__ (( section (".OpenFirmware") ))
static void OF_open (OF_env_t *OF_env)
{
    const unsigned char *args;
    unsigned char name[OF_NAMELEN_MAX], *namep;
    OF_node_t *node;
    OF_inst_t *inst;
    uint32_t ihandle;

    OF_CHECK_NBARGS(OF_env, 1);
    namep = (unsigned char *)popd(OF_env);
    OF_lds(name, namep);
    OF_DPRINTF("package [%s]\n", name);
    args = OF_get_args(OF_env, name);
    node = OF_get_alias(OF_env, name);
    if (node == NULL) {
        node = OF_pack_find_by_name(OF_env, OF_node_root, name);
    }
    if (node == NULL) {
        OF_DPRINTF("package not found !\n");
        pushd(OF_env, -1);
        return;
    }
    inst = OF_instance_new(OF_env, node);
    if (inst == NULL) {
        pushd(OF_env, -1);
        ERROR("Cannot create package instance\n");
        return;
    }
    ihandle = OF_instance_get_id(OF_env, inst);
    /* If an "open" method exists in the package, call it */
    OF_DPRINTF("package [%s] => %0x\n", name, ihandle);
    OF_node_put(OF_env, node);
    _OF_callmethod(OF_env, "open", ihandle, args);
}

/* De-instanciate a package */
__attribute__ (( section (".OpenFirmware") ))
static void OF_close (OF_env_t *OF_env)
{
    uint32_t ihandle;

    OF_CHECK_NBARGS(OF_env, 1);
    ihandle = popd(OF_env);
    /* If an "close" method exists in the package, call it */
    _OF_callmethod(OF_env, "close", ihandle, NULL);
    /* XXX: Should free the instance */
}

/* "read" */
__attribute__ (( section (".OpenFirmware") ))
static void OF_read (OF_env_t *OF_env)
{
    uint32_t ihandle;

    OF_CHECK_NBARGS(OF_env, 3);
    ihandle = popd(OF_env);
    OF_DPRINTF("ih: %0x\n", ihandle);
    /* If a "read" method exists in the package, call it */
    _OF_callmethod(OF_env, "read", ihandle, NULL);
}

/* Try call the "read" method of a device's package */
/* "write" */
__attribute__ (( section (".OpenFirmware") ))
static void OF_write (OF_env_t *OF_env)
{
    uint32_t ihandle;

    OF_CHECK_NBARGS(OF_env, 3);
    ihandle = popd(OF_env);
    //    OF_DPRINTF("ih: %0x\n", ihandle);
    /* If a "write" method exists in the package, call it */
    _OF_callmethod(OF_env, "write", ihandle, NULL);
}

/* "seek" */
__attribute__ (( section (".OpenFirmware") ))
static void OF_seek (OF_env_t *OF_env)
{
    uint32_t ihandle;

    OF_CHECK_NBARGS(OF_env, 3);
    ihandle = popd(OF_env);
    OF_DPRINTF("ih: %0x\n", ihandle);
    /* If a "seek" method exists in the package, call it */
    _OF_callmethod(OF_env, "seek", ihandle, NULL);
}

/* Memory services */
/* Claim some memory space */
__attribute__ (( section (".OpenFirmware") ))
uint32_t OF_claim_virt (uint32_t virt, uint32_t size, int *range)
{
    int i, keep = -1;

    OF_DPRINTF("Claim %d bytes at 0x%0x\n", size, virt);
    /* First check that the requested memory stands in the physical memory */
    if (OF_mem_ranges[0].start > virt ||
        (OF_mem_ranges[0].start + OF_mem_ranges[0].size) < (virt + size)) {
        ERROR("not in memory: start 0x%0x virt 0x%0x end 0x%0x 0x%0x\n",
              OF_mem_ranges[0].start, virt,
              OF_mem_ranges[0].start + OF_mem_ranges[0].size,
              virt + size);
        return (uint32_t)(-1);
    }
    /* Now check that it doesn't overlap with already claimed areas */
    for (i = 1; i < OF_MAX_MEMRANGES + 1; i++) {
        if (OF_mem_ranges[i].start == (uint32_t)(-1) ||
            OF_mem_ranges[i].size == (uint32_t)(-1)) {
            if (keep == -1)
                keep = i;
            continue;
        }
        if (OF_mem_ranges[i].start == virt &&
            (OF_mem_ranges[i].start + OF_mem_ranges[i].size) == (virt + size)) {
            return virt;
        }
        if (!((OF_mem_ranges[i].start >= (virt + size) ||
               (OF_mem_ranges[i].start + OF_mem_ranges[i].size) <= virt))) {
            ERROR("overlap: start 0x%0x virt 0x%0x end 0x%0x 0x%0x\n",
                  OF_mem_ranges[i].start, virt,
                  OF_mem_ranges[i].start + OF_mem_ranges[i].size,
                  virt + size);
            /* Aie... */
            return (uint32_t)(-1);
        }
    }
    OF_DPRINTF("return range: %d\n", keep);
    if (keep == -1) {
        /* no more rooms */
        ERROR("No more rooms\n");
        return (uint32_t)(-1);
    } else {
        ERROR("Give range: start 0x%0x 0x%0x\n", virt, size);
    }
    if (range != NULL)
        *range = keep;

    return virt;
}

/* We always try to get the upper address we can */
__attribute__ (( section (".OpenFirmware") ))
static uint32_t OF_claim_size (uint32_t size, int align, int *range)
{
    uint32_t addr, max = (uint32_t)(-1);
    int i;
    
    OF_DPRINTF("Try map %d bytes at 0x00000000\n", size);
    if (OF_claim_virt(0, size, range) != (uint32_t)(-1))
        max = 0;
    for (i = 1; i < OF_MAX_MEMRANGES + 1; i++) {
        if (OF_mem_ranges[i].start == (uint32_t)(-1) ||
            OF_mem_ranges[i].size == (uint32_t)(-1))
            continue;
        addr = (OF_mem_ranges[i].start + OF_mem_ranges[i].size + align - 1) &
            ~(align - 1);
        OF_DPRINTF("Try map %d bytes at 0x%0x\n", size, addr);
        if ((addr + 1) > (max + 1)) {
            if (OF_claim_virt(addr, size, range) != (uint32_t)(-1))
                max = addr;
        }
    }

    return max;
}

__attribute__ (( section (".OpenFirmware") ))
static void OF_claim (OF_env_t *OF_env)
{
    uint32_t virt, size, addr;
    int align;
    int i, range;

    OF_CHECK_NBARGS(OF_env, 3);
    virt = popd(OF_env);
    size = popd(OF_env);
    align = popd(OF_env);
    DPRINTF("virt 0x%0x size 0x%0x align %d\n", virt, size, align);
    if (align == 0) {
        addr = OF_claim_virt(virt, size, &range);
    } else {
        for (i = 1; i < align; i = i << 1)
            continue;
        align = i;
        size = (size + align - 1) & ~(align - 1);
        addr = OF_claim_size(size, align, &range);
    }
    if (addr == (uint32_t)-1) {
        ERROR("No range match !\n");
        pushd(OF_env, -1);
    }
    if (range != -1) {
        OF_mem_ranges[range].start = addr;
        OF_mem_ranges[range].size = size;
    }
    OF_DPRINTF("Give address 0x%0x\n", addr);
    pushd(OF_env, addr);
}

/* release some previously claimed memory */
__attribute__ (( section (".OpenFirmware") ))
static void OF_release (OF_env_t *OF_env)
{
    uint32_t virt, size;
    int i;

    OF_CHECK_NBARGS(OF_env, 2);
    virt = popd(OF_env);
    size = popd(OF_env);
    OF_DPRINTF("virt 0x%0x size 0x%0x\n", virt, size);
    for (i = 0; i < OF_MAX_MEMRANGES; i++) {
        if (OF_mem_ranges[i].start == virt && OF_mem_ranges[i].size == size) {
            OF_mem_ranges[i].start = (uint32_t)(-1);
            OF_mem_ranges[i].size = (uint32_t)(-1);
            break;
        }
    }
}

/* Control transfer services */
/* "boot" */

/* Enter Open-Firmware interpreter */
__attribute__ (( section (".OpenFirmware") ))
static void OF_enter (OF_env_t *OF_env)
{
    int n_args;

    n_args = stackd_depth(OF_env);
    /* means that the bootloader has ended.
     * So qemu will...
     */
    OF_DPRINTF("%d \n", n_args);
    //    printf("Bootloader has quitted...\n");
    //    abort();
}

/* Exit client program */
__attribute__ (( section (".OpenFirmware") ))
static void OF_exit (OF_env_t *OF_env)
{
    int n_args;

    n_args = stackd_depth(OF_env);
    /* means that the bootloader has ended.
     * So qemu will...
     */
    OF_DPRINTF("%d \n", n_args);
    //    printf("Bootloader has quitted...\n");
    //    abort();
}

/* "chain" */

/* User interface services */
/* "interpret" */

__attribute__ (( section (".OpenFirmware") ))
static void OF_interpret (OF_env_t *OF_env)
{
    const unsigned char *FString;
    void *buf;
    OF_inst_t *inst;
    OF_node_t *pks, *slw, *chs, *disp;
    uint32_t ihandle, crc;

    OF_DPRINTF("\n");
    //    OF_CHECK_NBARGS(OF_env, 1);
    FString = (const void *)popd(OF_env);
    crc = crc32(0, FString, strlen(FString));
    OF_DPRINTF("\n\nOF INTERPRETER CALL:\n [%s]\n crc=%0x\n", FString, crc);
    /* Do some hacks to make BootX happy */
    switch (crc) {
    case 0x225b6748: /* MacOS X 10.2 and OpenDarwin 1.41 */
    case 0xb1cd4d25: /* OpenDarwin 6.02 */
        /* Create "sl_words" package */
        popd(OF_env);
        /* Find "/packages" */
        pks = OF_pack_find_by_name(OF_env, OF_node_root, "/packages");
        if (pks == NULL) {
            OF_node_put(OF_env, pks);
            pushd(OF_env, -1);
            ERROR("Cannot get '/packages'\n");
            break;
        }
        slw = OF_node_new(OF_env, pks, "sl_words", OF_ADDRESS_NONE);
        if (slw == NULL) {
            OF_node_put(OF_env, pks);
            pushd(OF_env, -1);
            ERROR("Cannot create 'sl_words'\n");
            break;
        }
        /* Create methods */
        OF_method_new(OF_env, slw, "slw_set_output_level",
                      &slw_set_output_level);
        OF_method_new(OF_env, slw, "slw_emit", &slw_emit);
        OF_method_new(OF_env, slw, "slw_cr", &slw_cr);
        OF_method_new(OF_env, slw, "slw_init_keymap", &slw_init_keymap);
        OF_method_new(OF_env, slw, "slw_update_keymap", &slw_update_keymap);
        OF_method_new(OF_env, slw, "slw_spin", &slw_spin);
        OF_method_new(OF_env, slw, "slw_spin_init", &slw_spin_init);
        OF_method_new(OF_env, slw, "slw_pwd", &slw_pwd);
        OF_method_new(OF_env, slw, "slw_sum", &slw_sum);
        /* Init properties */
        OF_prop_int_new(OF_env, slw, "outputLevel", 0);
        OF_prop_int_new(OF_env, slw, "keyboardIH", 0);
        {
#if 0
            OF_node_t *kbd;
            kbd = OF_pack_find_by_name(OF_env, OF_node_root, "/keyboard");
            if (kbd == NULL) {
                OF_node_put(OF_env, pks);
                pushd(OF_env, -1);
                ERROR("Cannot get '/keyboard'\n");
                break;
            }
            buf = malloc(0x20);
            if (buf == NULL) {
                OF_node_put(OF_env, pks);
                pushd(OF_env, -1);
                ERROR("Cannot allocate keyboard buff\n");
                break;
            }
#else
            buf = malloc(0x20);
            if (buf == NULL) {
                OF_node_put(OF_env, pks);
                pushd(OF_env, -1);
                ERROR("Cannot allocate keyboard buff\n");
                break;
            }
            memset(buf, 0, 0x20);
            OF_property_new(OF_env, slw, "keyMap", buf, 0x20);
#endif
        }
        OF_prop_int_new(OF_env, slw, "screenIH", 0);
        OF_prop_int_new(OF_env, slw, "cursorAddr", 0);
        OF_prop_int_new(OF_env, slw, "cursorX", 0);
        OF_prop_int_new(OF_env, slw, "cursorY", 0);
        OF_prop_int_new(OF_env, slw, "cursorW", 0);
        OF_prop_int_new(OF_env, slw, "cursorH", 0);
        OF_prop_int_new(OF_env, slw, "cursorFrames", 0);
        OF_prop_int_new(OF_env, slw, "cursorPixelSize", 0);
        OF_prop_int_new(OF_env, slw, "cursorStage", 0);
        OF_prop_int_new(OF_env, slw, "cursorTime", 0);
        OF_prop_int_new(OF_env, slw, "cursorDelay", 0);
        /* Instanciate sl_words */
        inst = OF_instance_new(OF_env, slw);
        if (inst == NULL) {
            OF_node_put(OF_env, pks);
            pushd(OF_env, -1);
            ERROR("Cannot create sl_words instance\n");
            break;
        }
        ihandle = OF_instance_get_id(OF_env, inst);
        /* Release packages */
        OF_node_put(OF_env, slw);
        OF_node_put(OF_env, pks);
        OF_DPRINTF("sl_words instance: %0x\n", ihandle);
        /* Set return value */
        if (crc == 0xb1cd4d25) /* Hack for OpenDarwin 6.02 */
            pushd(OF_env, ihandle);
        pushd(OF_env, ihandle);
        pushd(OF_env, 0);
        break;
    case 0x233441d3: /* MacOS X 10.2 and OpenDarwin 1.41 */
        /* Create "memory-map" pseudo device */
        {
            OF_node_t *map;
            uint32_t phandle;

        /* Find "/packages" */
        chs = OF_pack_find_by_name(OF_env, OF_node_root, "/chosen");
        if (chs == NULL) {
            pushd(OF_env, -1);
            ERROR("Cannot get '/chosen'\n");
            break;
        }
            map = OF_node_new(OF_env, chs, "memory-map", OF_ADDRESS_NONE);
            if (map == NULL) {
                pushd(OF_env, -1);
                ERROR("Cannot create 'memory-map'\n");
                break;
            }
            phandle = OF_pack_handle(OF_env, map);
            OF_node_put(OF_env, map);
            OF_node_put(OF_env, chs);
            pushd(OF_env, phandle);
        pushd(OF_env, 0);
        }
        break;
    case 0x32a2d18e: /* MacOS X 10.2 and OpenDarwin 6.02 */
        /* Return screen ihandle */
        disp = OF_get_alias(OF_env, "screen");
        if (disp == NULL) {
            pushd(OF_env, 0);
            pushd(OF_env, -1);
            ERROR("Cannot get 'screen' alias\n");
            break;
        }
        inst = OF_instance_new(OF_env, disp);
        if (inst == NULL) {
            OF_node_put(OF_env, disp);
            pushd(OF_env, 0);
            pushd(OF_env, -1);
            ERROR("Cannot create 'screen' instance\n");
            break;
        }
        ihandle = OF_instance_get_id(OF_env, inst);
        OF_node_put(OF_env, disp);
        OF_DPRINTF("Return screen ihandle: %0x\n", ihandle);
        pushd(OF_env, ihandle);
        pushd(OF_env, 0);
        break;
    case 0xF3A9841F: /* MacOS X 10.2 */
    case 0x76fbdf18: /* OpenDarwin 6.02 */
        /* Set current display as active package */
        disp = OF_get_alias (OF_env, "screen");
        if (disp == NULL) {
            pushd(OF_env, 0);
            pushd(OF_env, -1);
        }
        OF_node_put(OF_env, disp);
        break;
    case 0x1c3bc93f: /* MacOS X 10.3 */
        /* get-package-property if 0 0 then */
        OF_getprop(OF_env);
        {
            uint32_t len;
            len = popd(OF_env);
            if (len == (uint32_t)-1)
                len = 0;
            pushd(OF_env, len);
        }
        break;
    case 0x218d5ccb: /* yaboot */
    case 0x27b32255:
    case 0x05d332ef:
    case 0xc7b5d3b5:
        /* skip it */
        break;
    case 0xf541a878:
    case 0x6a9b2be6:
        /* Yaboot: set background color to black */
        break;
    case 0x846077fb:
    case 0x299c2c5d: /* gentoo */
        /* Yaboot: set foreground color to grey */
        break;
    case 0x4ad41f2d:
        /* Yaboot: wait 10 ms: sure ! */
        break;

    default:
        /* ERROR */
        printf("Script: len=%d\n%s\n", (int)strlen(FString), FString);
        printf("Call %0x NOT IMPLEMENTED !\n", crc);
        bug();
        break;
    }
    OF_DPRINTF("\n\nOF INTERPRETER CALL DONE\n\n");
}

/* "set-callback" */
/* "set-symbol-lookup" */

/* Time services */
/* "milliseconds" */
__attribute__ (( section (".OpenFirmware") ))
static void OF_milliseconds (OF_env_t *OF_env)
{
#if 0
    struct timeval tv;

    OF_DPRINTF("\n");
    OF_CHECK_NBARGS(OF_env, 0);
    gettimeofday(&tv, NULL);
    pushd(OF_env, (tv.tv_sec * 1000) + (tv.tv_usec / 1000));
#else
    static uint32_t ms = 0;

    OF_CHECK_NBARGS(OF_env, 0);
    pushd(OF_env, ms);
    usleep(10000); /* XXX: TOFIX: Random sleep */
    ms += 10;
#endif
}

/* Undocumented in IEEE 1275 */
__attribute__ (( section (".OpenFirmware") ))
static void OF_quiesce (OF_env_t *OF_env)
{
    OF_CHECK_NBARGS(OF_env, 0);
    /* Should free all OF resources */
    bd_reset_all();
#if defined (DEBUG_BIOS)
    {
        uint16_t loglevel = 0x02 | 0x10 | 0x80;
        //        outw(0xFF02, loglevel);
        outb(0x0F02, loglevel);
    }
#endif
}

typedef struct OF_service_t OF_service_t;
struct OF_service_t {
    const unsigned char *name;
    OF_cb_t cb;
};

static OF_service_t services[] = {
    { "test",                &OF_test,                },
    { "peer",                &OF_peer,                },
    { "child",               &OF_child,               },
    { "parent",              &OF_parent,              },
    { "instance-to-package", &OF_instance_to_package, },
    { "getproplen",          &OF_getproplen,          },
    { "getprop",             &OF_getprop,             },
    { "nextprop",            &OF_nextprop,            },
    { "setprop",             &OF_setprop,             },
    { "finddevice",          &OF_finddevice,          },
    { "instance-to-path",    &OF_instance_to_path,    },
    { "package-to-path",     &OF_package_to_path,     },
    { "call-method",         &OF_callmethod,          },
    { "open",                &OF_open,                },
    { "open-package",        &OF_open,                },
    { "close",               &OF_close,               },
    { "read",                &OF_read,                },
    { "write",               &OF_write,               },
    { "seek",                &OF_seek,                },
    { "claim",               &OF_claim,               },
    { "release",             &OF_release,             },
    { "enter",               &OF_enter,               },
    { "exit",                &OF_exit,                },
    { "interpret",           &OF_interpret,           },
    { "milliseconds",        &OF_milliseconds,        },
    { "quiesce",             &OF_quiesce,             },
};

/* Probe if a named service exists */
__attribute__ (( section (".OpenFirmware") ))
static void OF_test (OF_env_t *OF_env)
{
    unsigned char name[OF_NAMELEN_MAX], *namep;
    uint32_t i;
    int ret = -1;

    OF_CHECK_NBARGS(OF_env, 1);
    namep = (unsigned char *)popd(OF_env);
    OF_lds(name, namep);
    OF_DPRINTF("service [%s]\n", name);
    for (i = 0; i < (sizeof(services) / sizeof(OF_service_t)); i++) {
        if (strcmp(services[i].name, name) == 0) {
            ret = 0;
            break;
        }
    }
    pushd(OF_env, ret);
}

/* Main entry point for PPC clients */
__attribute__ (( section (".OpenFirmware") ))
int OF_client_entry (void *p)
{
    unsigned char buffer[OF_NAMELEN_MAX];
    OF_env_t OF_env;
    OF_cb_t cb;
    unsigned char *namep;
    uint32_t i;

    /* set our environment */
    MMU_off();
    OF_DPRINTF("Called with arg: %p\n", p);
    /* Load function name string */
    namep = (unsigned char *)(*(uint32_t *)p);
    OF_lds(buffer, namep);
    /* Find callback */
    cb = NULL;
    OF_DPRINTF("Look for service [%s]\n", buffer);
    for (i = 0; i < (sizeof(services) / sizeof(OF_service_t)); i++) {
        if (strcmp(services[i].name, buffer) == 0) {
            cb = services[i].cb;
            break;
        }
    }
    if (cb == NULL) {
        OF_DPRINTF("service [%s] not implemented\n", buffer);
        //        bug();
        return -1;
    }
#if 0
    OF_DPRINTF("Service [%s] found\n", buffer);
#endif
    /* Set up stack *NON REENTRANT* */
    OF_env_init(&OF_env);
    /* Launch Forth glue */
    C_to_Forth(&OF_env, (uint32_t *)p + 1, &cb);
    OF_DPRINTF("done\n");
    MMU_on();

    return 0;
}

/*****************************************************************************/
/* Run-time abstraction services */
/* RTAS RAM is organised this way:
 * RTAS_memory is given by the OS when instanciating RTAS.
 * it's an 32 kB area divided in 2 zones:
 * Up is a stack, used to call RTAS services
 * Down is the variables area.
 */

__attribute__ (( section (".RTAS_vars") ))
static OF_cb_t *RTAS_callbacks[32];
#if 0
__attribute__ (( section (".RTAS_vars") ))
static uint8_t *RTAS_base;
#endif

/* RTAS is called in real mode (ie no MMU), privileged with all exceptions
 * disabled. It has to preserve all registers except R3 to R12.
 * The OS should ensure it's not re-entered.
 */
__attribute__ (( section (".RTAS") ))
int RTAS_entry (void *p)
{
    OF_env_t RTAS_env;
    uint32_t token;

    OF_DPRINTF("Called with arg: %p\n", p);
    /* set our environment */
    token = *(uint32_t *)p;
    /* Set up stack */
    RTAS_env.stackb = (uint32_t *)(RTAS_memory + 0x8000 - 4);
    RTAS_env.stackp = RTAS_env.stackb;
    RTAS_env.funcb = (uint32_t *)(RTAS_memory + 0x8000 - OF_STACK_SIZE - 4);
    RTAS_env.funcp = RTAS_env.funcb;
    /* Call Forth glue */
    C_to_Forth(&RTAS_env, (uint32_t *)p + 1, RTAS_callbacks[token & 0x3F]);
    OF_DPRINTF("done\n");

    return 0;
}

__attribute__ (( section (".RTAS") ))
static void RTAS_restart_rtas (OF_env_t *RTAS_env)
{
    OF_DPRINTF("\n");
    OF_CHECK_NBARGS(RTAS_env, 0);
    /* No implementation: return error */
    pushd(RTAS_env, -1);
}

__attribute__ (( section (".RTAS") ))
static void RTAS_nvram_fetch (OF_env_t *RTAS_env)
{
    uint8_t *buffer;
    int offset, length;
    int i;

    OF_DPRINTF("\n");
    OF_CHECK_NBARGS(RTAS_env, 3);
    offset = popd(RTAS_env);
    buffer = (uint8_t *)popd(RTAS_env);
    length = popd(RTAS_env);
    for (i = 0; i < length; i++) {
        if ((i + offset) >= NVRAM_get_size(nvram)) {
            pushd(RTAS_env, -3);
            return;
        }
        *buffer++ = NVRAM_read(nvram, i + offset);
    }
    pushd(RTAS_env, length);
}

__attribute__ (( section (".RTAS") ))
static void RTAS_nvram_store (OF_env_t *RTAS_env)
{
    uint8_t *buffer;
    int offset, length;
    int i;

    OF_DPRINTF("\n");
    OF_CHECK_NBARGS(RTAS_env, 3);
    offset = popd(RTAS_env);
    buffer = (uint8_t *)popd(RTAS_env);
    length = popd(RTAS_env);
    for (i = 0; i < length; i++) {
        if ((i + offset) >= NVRAM_get_size(nvram)) {
            pushd(RTAS_env, -3);
            return;
        }
        NVRAM_write(nvram, i + offset, *buffer++);
    }
    pushd(RTAS_env, length);
}

__attribute__ (( section (".RTAS") ))
static void RTAS_get_time_of_day (OF_env_t *RTAS_env)
{
#if 0
    struct tm tm;
    time_t t;

    OF_DPRINTF("\n");
    OF_CHECK_NBARGS(RTAS_env, 0);
    t = get_time();
    localtime_r(&t, &tm);
    pushd(RTAS_env, 0); /* nanoseconds */
    pushd(RTAS_env, tm.tm_sec);
    pushd(RTAS_env, tm.tm_min);
    pushd(RTAS_env, tm.tm_hour);
    pushd(RTAS_env, tm.tm_mday);
    pushd(RTAS_env, tm.tm_mon);
    pushd(RTAS_env, tm.tm_year);
    pushd(RTAS_env, 0); /* status */
#else
    pushd(RTAS_env, 0);
    pushd(RTAS_env, 0);
    pushd(RTAS_env, 0);
    pushd(RTAS_env, 0);
    pushd(RTAS_env, 0);
    pushd(RTAS_env, 0);
    pushd(RTAS_env, 0);
    pushd(RTAS_env, 0);
#endif
}

__attribute__ (( section (".RTAS") ))
static void RTAS_set_time_of_day (OF_env_t *RTAS_env)
{
#if 0
    struct tm tm;
    time_t t;

    OF_DPRINTF("\n");
    OF_CHECK_NBARGS(RTAS_env, 7);
    tm.tm_year = popd(RTAS_env);
    tm.tm_mon = popd(RTAS_env);
    tm.tm_mday = popd(RTAS_env);
    tm.tm_hour = popd(RTAS_env);
    tm.tm_min = popd(RTAS_env);
    tm.tm_sec = popd(RTAS_env);
    popd(RTAS_env); /* nanoseconds */
    t = mktime(&tm);
    set_time_offset(t);
#endif
    pushd(RTAS_env, 0); /* status */
}

__attribute__ (( section (".RTAS") ))
static void RTAS_set_time_for_power_on (OF_env_t *RTAS_env)
{
    OF_DPRINTF("\n");
    OF_CHECK_NBARGS(RTAS_env, 7);
    /* Do nothing */
    pushd(RTAS_env, 0); /* status */
}

__attribute__ (( section (".RTAS") ))
static void RTAS_event_scan (OF_env_t *RTAS_env)
{
    OF_DPRINTF("\n");
    OF_CHECK_NBARGS(RTAS_env, 4);
    /* Pretend there are no new events */
    pushd(RTAS_env, 1);
}

__attribute__ (( section (".RTAS") ))
static void RTAS_check_exception (OF_env_t *RTAS_env)
{
    OF_DPRINTF("\n");
    OF_CHECK_NBARGS(RTAS_env, 6);
    /* Pretend we found no exceptions */
    pushd(RTAS_env, 1);
}

__attribute__ (( section (".RTAS") ))
static void RTAS_read_pci_config (OF_env_t *RTAS_env)
{
    OF_DPRINTF("\n");
    OF_CHECK_NBARGS(RTAS_env, 2);
    /* Hardware error */
    pushd(RTAS_env, -1);
}

__attribute__ (( section (".RTAS") ))
static void RTAS_write_pci_config (OF_env_t *RTAS_env)
{
    OF_DPRINTF("\n");
    OF_CHECK_NBARGS(RTAS_env, 3);
    /* Hardware error */
    pushd(RTAS_env, -1);
}

__attribute__ (( section (".RTAS") ))
static void RTAS_display_character (OF_env_t *RTAS_env)
{
    int c;

    OF_DPRINTF("\n");
    OF_CHECK_NBARGS(RTAS_env, 1);
    c = popd(RTAS_env);
#if 0
    printf("%c", c);
#else
    outb(0x0F00, c);
#endif
    pushd(RTAS_env, 0);
}

__attribute__ (( section (".RTAS") ))
static void RTAS_set_indicator (OF_env_t *RTAS_env)
{
    const unsigned char *name;
    int indic, state;

    OF_DPRINTF("\n");
    OF_CHECK_NBARGS(RTAS_env, 3);
    indic = popd(RTAS_env);
    state = popd(RTAS_env);
    switch (indic) {
    case 1:
        name = "tone frequency";
        break;
    case 2:
        name = "tone volume";
        break;
    case 3:
        name = "system power state";
        break;
    case 4:
        name = "warning light";
        break;
    case 5:
        name = "disk activity light";
        break;
    case 6:
        name = "hexadecimal display unit";
        break;
    case 7:
        name = "batery warning time";
        break;
    case 8:
        name = "condition cycle request";
        break;
    case 9000 ... 9999:
        name = "vendor specific";
        break;
    default:
        pushd(RTAS_env, -3);
        return;
    }        
    OF_DPRINTF("Set indicator %d [%s] to %d\n", indic, name, state);
    pushd(RTAS_env, 0);
}

__attribute__ (( section (".RTAS") ))
static void RTAS_get_sensor_state (OF_env_t *RTAS_env)
{
    const unsigned char *name;
    int type, index;
    int state;

    OF_DPRINTF("\n");
    OF_CHECK_NBARGS(RTAS_env, 2);
    type = popd(RTAS_env);
    index = popd(RTAS_env);
    switch (index) {
    case 1:
        name = "key switch";
        state = 1; /* Normal */
        break;
    case 2:
        name = "enclosure switch";
        state = 0; /* Closed */
        break;
    case 3:
        name = "thermal sensor";
        state = 40; /* in degrees Celsius (not too hot !) */
        break;
    case 4:
        name = "lid status";
        state = 1; /* Open */
        break;
    case 5:
        name = "power source";
        state = 0; /* AC */
        break;
    case 6:
        name = "battery voltage";
        state = 6; /* Let's have a moderated answer :-) */
        break;
    case 7:
        name = "battery capacity remaining";
        state = 3; /* High */
        break;
    case 8:
        name = "battery capacity percentage";
        state = 1000; /* 100 % */
        break;
    case 9:
        name = "EPOW sensor";
        state = 5; /* ? */
        break;
    case 10:
        name = "battery condition cycle state";
        state = 0; /* none */
        break;
    case 11:
        name = "battery charge state";
        state = 2; /* No current flow */
        break;
    case 9000 ... 9999:
        name = "vendor specific";
        state = 0;
        break;
    default:
        pushd(RTAS_env, -3);
        return;
    }        
    OF_DPRINTF("Pretend sensor %d [%s] is in state %d\n", index, name, state);
    pushd(RTAS_env, state);
    pushd(RTAS_env, 0);
}

#if 0 // No power management */
__attribute__ (( section (".RTAS") ))
static void RTAS_set_power_level (OF_env_t *RTAS_env)
{
    OF_DPRINTF("\n");
}

__attribute__ (( section (".RTAS") ))
static void RTAS_get_power_level (OF_env_t *RTAS_env)
{
    OF_DPRINTF("\n");
}

__attribute__ (( section (".RTAS") ))
static void RTAS_assume_power_management (OF_env_t *RTAS_env)
{
    OF_DPRINTF("\n");
}

__attribute__ (( section (".RTAS") ))
static void RTAS_relinquish_power_management (OF_env_t *RTAS_env)
{
    OF_DPRINTF("\n");
}
#endif

__attribute__ (( section (".RTAS") ))
static void RTAS_power_off (OF_env_t *RTAS_env)
{
    printf("RTAS was asked to switch off\n");
    OF_CHECK_NBARGS(RTAS_env, 2);
    //    abort();
}

__attribute__ (( section (".RTAS") ))
static void RTAS_suspend (OF_env_t *RTAS_env)
{
    OF_DPRINTF("\n");
    OF_CHECK_NBARGS(RTAS_env, 3);
    /* Pretend we don't succeed */
    pushd(RTAS_env, -1);
}

__attribute__ (( section (".RTAS") ))
static void RTAS_hibernate (OF_env_t *RTAS_env)
{
    OF_DPRINTF("\n");
    OF_CHECK_NBARGS(RTAS_env, 3);
    /* Pretend we don't succeed */
    pushd(RTAS_env, -1);
}

__attribute__ (( section (".RTAS") ))
static void RTAS_system_reboot (OF_env_t *RTAS_env)
{
    printf("RTAS was asked to reboot\n");
    OF_CHECK_NBARGS(RTAS_env, 0);
    //    abort();
}

#if 0 // No power management nor SMP */
__attribute__ (( section (".RTAS") ))
static void RTAS_cache_control (OF_env_t *RTAS_env)
{
    OF_DPRINTF("\n");
}

__attribute__ (( section (".RTAS") ))
static void RTAS_freeze_time_base (OF_env_t *RTAS_env)
{
    OF_DPRINTF("\n");
}

__attribute__ (( section (".RTAS") ))
static void RTAS_thaw_time_base (OF_env_t *RTAS_env)
{
    OF_DPRINTF("\n");
}

__attribute__ (( section (".RTAS") ))
static void RTAS_stop_self (OF_env_t *RTAS_env)
{
    OF_DPRINTF("\n");
}

__attribute__ (( section (".RTAS") ))
static void RTAS_start_cpu (OF_env_t *RTAS_env)
{
    OF_DPRINTF("\n");
}
#endif

__attribute__ (( section (".RTAS") ))
static void RTAS_instantiate (OF_env_t *RTAS_env)
{
    const unsigned char *args;
    uint32_t ihandle;
    uint32_t base_address;

    OF_DPRINTF("\n");
    OF_CHECK_NBARGS(RTAS_env, 3);
    ihandle = popd(RTAS_env);
    args = (void *)popd(RTAS_env);
    base_address = popd(RTAS_env);
    memmove((void *)base_address, (void *)(&_RTAS_start),
            (char *)(&_RTAS_data_end) - (char *)(&_RTAS_start));
    OF_DPRINTF("base_address=0x%0x\n", base_address);
    pushd(RTAS_env, base_address);
    pushd(RTAS_env, 0);
}

__attribute__ (( section (".RTAS") ))
static void RTAS_new_cb (OF_env_t *env, OF_node_t *rtas,
                         const unsigned char *name,
                         OF_cb_t cb, uint32_t *token_next)
{
    OF_prop_int_new(env, rtas, name, 0xabcd0000 | *token_next);
    RTAS_callbacks[*token_next] = &cb;
    (*token_next)++;
}

__attribute__ (( section (".RTAS") ))
void RTAS_init (void)
{
    OF_env_t *RTAS_env;
    OF_node_t *rtas, *chs;
    OF_prop_t *stdout;
    uint32_t token_next = 0, size;

    RTAS_env = OF_env_main;
    rtas = OF_node_new(RTAS_env, OF_node_root, "rtas", OF_ADDRESS_NONE);
    if (rtas == NULL) {
        ERROR("RTAS not found\n");
        return;
    }
    size = ((char *)(&_RTAS_data_end) - (char *)(&_RTAS_start) + 0x0000FFFF) &
        ~0x0000FFFF;
    OF_DPRINTF("RTAS size: %d bytes (%d)\n", size,
               (char *)(&_RTAS_data_end) - (char *)(&_RTAS_start));
    OF_prop_int_new(RTAS_env, rtas, "rtas-size", size);
    OF_prop_int_new(RTAS_env, rtas, "rtas-version", 1);
    OF_prop_int_new(RTAS_env, rtas, "rtas-event-scan-rate", 0);
    OF_prop_int_new(RTAS_env, rtas, "rtas-error-log-max", 0);
    chs = OF_node_get(RTAS_env, "chosen");
    if (chs == NULL) {
        ERROR("choosen not found\n");
        return;
    }
    stdout = OF_property_get(RTAS_env, chs, "stdout");
    if (stdout == NULL) {
        OF_node_put(RTAS_env, chs);
        ERROR("stdout not found\n");
        return;
    }
    OF_prop_int_new(RTAS_env, rtas, "rtas-display-device",
                    *(uint32_t *)stdout->value);
    /* RTAS tokens */
    RTAS_new_cb(RTAS_env, rtas, "restart_rtas",
                &RTAS_restart_rtas, &token_next);
    RTAS_new_cb(RTAS_env, rtas, "nvram_fetch",
                &RTAS_nvram_fetch, &token_next);
    RTAS_new_cb(RTAS_env, rtas, "nvram_store",
                &RTAS_nvram_store, &token_next);
    RTAS_new_cb(RTAS_env, rtas, "get-time-of_day",
                &RTAS_get_time_of_day, &token_next);
    RTAS_new_cb(RTAS_env, rtas, "set-time-of-day",
                &RTAS_set_time_of_day, &token_next);
    RTAS_new_cb(RTAS_env, rtas, "set-time-for-power-on",
                &RTAS_set_time_for_power_on, &token_next);
    RTAS_new_cb(RTAS_env, rtas, "event-scan", &RTAS_event_scan, &token_next);
    RTAS_new_cb(RTAS_env, rtas, "check-exception",
                &RTAS_check_exception, &token_next);
    RTAS_new_cb(RTAS_env, rtas, "read-pci-config",
                &RTAS_read_pci_config, &token_next);
    RTAS_new_cb(RTAS_env, rtas, "write-pci-config",
                &RTAS_write_pci_config, &token_next);
    RTAS_new_cb(RTAS_env, rtas, "display-character",
                &RTAS_display_character, &token_next);
    RTAS_new_cb(RTAS_env, rtas, "set-indicator",
                &RTAS_set_indicator, &token_next);
    RTAS_new_cb(RTAS_env, rtas, "get-sensor-state",
                &RTAS_get_sensor_state, &token_next);
#if 0 // No power management */
    RTAS_new_cb(RTAS_env, rtas, "set-power-level",
                &RTAS_set_power_level, &token_next);
    RTAS_new_cb(RTAS_env, rtas, "get-power-level",
                &RTAS_get_power_level, &token_next);
    RTAS_new_cb(RTAS_env, rtas, "assume-power-management",
                &RTAS_assume_power_management, &token_next);
    RTAS_new_cb(RTAS_env, rtas, "relinquish-power-management",
                &RTAS_relinquish_power_management, &token_next);
#endif
    RTAS_new_cb(RTAS_env, rtas, "power-off", &RTAS_power_off, &token_next);
    RTAS_new_cb(RTAS_env, rtas, "suspend", &RTAS_suspend, &token_next);
    RTAS_new_cb(RTAS_env, rtas, "hibernate", &RTAS_hibernate, &token_next);
    RTAS_new_cb(RTAS_env, rtas, "system-reboot",
                &RTAS_system_reboot, &token_next);
#if 0 // No power management nor SMP */
    RTAS_new_cb(RTAS_env, rtas, "cache-control",
                &RTAS_cache_control, &token_next);
    RTAS_new_cb(RTAS_env, rtas, "freeze_time_base",
                &RTAS_freeze_time_base, &token_next);
    RTAS_new_cb(RTAS_env, rtas, "thaw_time_base",
                &RTAS_thaw_time_base, &token_next);
    RTAS_new_cb(RTAS_env, rtas, "stop-self", &RTAS_stop_self, &token_next);
    RTAS_new_cb(RTAS_env, rtas, "start-cpu", &RTAS_start_cpu, &token_next);
#endif
    /* missing
     * "update-flash"
     * "update-flash-and-reboot"
     * "query-cpu-stopped-state" for SMP
     */
    OF_method_new(RTAS_env, rtas, "instantiate-rtas", &RTAS_instantiate);
    OF_node_put(RTAS_env, rtas);
    OF_node_new(RTAS_env, OF_node_root, "nomore", OF_ADDRESS_NONE);
    DPRINTF("RTAS done\n");
}

/*****************************************************************************/
/*                          That's all for now...                            */
/*****************************************************************************/
