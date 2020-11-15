#ifndef __VGAHW_H
#define __VGAHW_H

#include "types.h" // u8
#include "config.h" // CONFIG_*

#include "cbvga.h" // cbvga_setup
#include "clext.h" // clext_set_mode
#include "bochsvga.h" // bochsvga_set_mode
#include "stdvga.h" // stdvga_set_mode
#include "geodevga.h" // geodevga_setup

static inline struct vgamode_s *vgahw_find_mode(int mode) {
    if (CONFIG_VGA_CIRRUS)
        return clext_find_mode(mode);
    if (CONFIG_VGA_BOCHS)
        return bochsvga_find_mode(mode);
    if (CONFIG_VGA_COREBOOT)
        return cbvga_find_mode(mode);
    return stdvga_find_mode(mode);
}

static inline int vgahw_set_mode(struct vgamode_s *vmode_g, int flags) {
    if (CONFIG_VGA_CIRRUS)
        return clext_set_mode(vmode_g, flags);
    if (CONFIG_VGA_BOCHS)
        return bochsvga_set_mode(vmode_g, flags);
    if (CONFIG_VGA_COREBOOT)
        return cbvga_set_mode(vmode_g, flags);
    return stdvga_set_mode(vmode_g, flags);
}

static inline void vgahw_list_modes(u16 seg, u16 *dest, u16 *last) {
    if (CONFIG_VGA_CIRRUS)
        clext_list_modes(seg, dest, last);
    else if (CONFIG_VGA_BOCHS)
        bochsvga_list_modes(seg, dest, last);
    else if (CONFIG_VGA_COREBOOT)
        cbvga_list_modes(seg, dest, last);
    else
        stdvga_list_modes(seg, dest, last);
}

static inline int vgahw_setup(void) {
    if (CONFIG_VGA_CIRRUS)
        return clext_setup();
    if (CONFIG_VGA_BOCHS)
        return bochsvga_setup();
    if (CONFIG_VGA_GEODEGX2 || CONFIG_VGA_GEODELX)
        return geodevga_setup();
    if (CONFIG_VGA_COREBOOT)
        return cbvga_setup();
    return stdvga_setup();
}

static inline int vgahw_get_window(struct vgamode_s *vmode_g, int window) {
    if (CONFIG_VGA_CIRRUS)
        return clext_get_window(vmode_g, window);
    if (CONFIG_VGA_BOCHS)
        return bochsvga_get_window(vmode_g, window);
    if (CONFIG_VGA_COREBOOT)
        return cbvga_get_window(vmode_g, window);
    return stdvga_get_window(vmode_g, window);
}

static inline int vgahw_set_window(struct vgamode_s *vmode_g, int window
                                   , int val) {
    if (CONFIG_VGA_CIRRUS)
        return clext_set_window(vmode_g, window, val);
    if (CONFIG_VGA_BOCHS)
        return bochsvga_set_window(vmode_g, window, val);
    if (CONFIG_VGA_COREBOOT)
        return cbvga_set_window(vmode_g, window, val);
    return stdvga_set_window(vmode_g, window, val);
}

static inline int vgahw_get_linelength(struct vgamode_s *vmode_g) {
    if (CONFIG_VGA_CIRRUS)
        return clext_get_linelength(vmode_g);
    if (CONFIG_VGA_BOCHS)
        return bochsvga_get_linelength(vmode_g);
    if (CONFIG_VGA_COREBOOT)
        return cbvga_get_linelength(vmode_g);
    return stdvga_get_linelength(vmode_g);
}

static inline int vgahw_set_linelength(struct vgamode_s *vmode_g, int val) {
    if (CONFIG_VGA_CIRRUS)
        return clext_set_linelength(vmode_g, val);
    if (CONFIG_VGA_BOCHS)
        return bochsvga_set_linelength(vmode_g, val);
    if (CONFIG_VGA_COREBOOT)
        return cbvga_set_linelength(vmode_g, val);
    return stdvga_set_linelength(vmode_g, val);
}

static inline int vgahw_get_displaystart(struct vgamode_s *vmode_g) {
    if (CONFIG_VGA_CIRRUS)
        return clext_get_displaystart(vmode_g);
    if (CONFIG_VGA_BOCHS)
        return bochsvga_get_displaystart(vmode_g);
    if (CONFIG_VGA_COREBOOT)
        return cbvga_get_displaystart(vmode_g);
    return stdvga_get_displaystart(vmode_g);
}

static inline int vgahw_set_displaystart(struct vgamode_s *vmode_g, int val) {
    if (CONFIG_VGA_CIRRUS)
        return clext_set_displaystart(vmode_g, val);
    if (CONFIG_VGA_BOCHS)
        return bochsvga_set_displaystart(vmode_g, val);
    if (CONFIG_VGA_COREBOOT)
        return cbvga_set_displaystart(vmode_g, val);
    return stdvga_set_displaystart(vmode_g, val);
}

static inline int vgahw_get_dacformat(struct vgamode_s *vmode_g) {
    if (CONFIG_VGA_BOCHS)
        return bochsvga_get_dacformat(vmode_g);
    if (CONFIG_VGA_COREBOOT)
        return cbvga_get_dacformat(vmode_g);
    return stdvga_get_dacformat(vmode_g);
}

static inline int vgahw_set_dacformat(struct vgamode_s *vmode_g, int val) {
    if (CONFIG_VGA_BOCHS)
        return bochsvga_set_dacformat(vmode_g, val);
    if (CONFIG_VGA_COREBOOT)
        return cbvga_set_dacformat(vmode_g, val);
    return stdvga_set_dacformat(vmode_g, val);
}

static inline int vgahw_save_restore(int cmd, u16 seg, void *data) {
    if (CONFIG_VGA_CIRRUS)
        return clext_save_restore(cmd, seg, data);
    if (CONFIG_VGA_BOCHS)
        return bochsvga_save_restore(cmd, seg, data);
    if (CONFIG_VGA_COREBOOT)
        return cbvga_save_restore(cmd, seg, data);
    return stdvga_save_restore(cmd, seg, data);
}

#endif // vgahw.h
