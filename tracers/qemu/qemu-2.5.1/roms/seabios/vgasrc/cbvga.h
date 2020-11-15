#ifndef __CBVGA_H
#define __CBVGA_H

#include "types.h" // u16

struct vgamode_s *cbvga_find_mode(int mode);
void cbvga_list_modes(u16 seg, u16 *dest, u16 *last);
int cbvga_get_window(struct vgamode_s *vmode_g, int window);
int cbvga_set_window(struct vgamode_s *vmode_g, int window, int val);
int cbvga_get_linelength(struct vgamode_s *vmode_g);
int cbvga_set_linelength(struct vgamode_s *vmode_g, int val);
int cbvga_get_displaystart(struct vgamode_s *vmode_g);
int cbvga_set_displaystart(struct vgamode_s *vmode_g, int val);
int cbvga_get_dacformat(struct vgamode_s *vmode_g);
int cbvga_set_dacformat(struct vgamode_s *vmode_g, int val);
int cbvga_save_restore(int cmd, u16 seg, void *data);
int cbvga_set_mode(struct vgamode_s *vmode_g, int flags);
int cbvga_setup(void);

#endif // cbvga.h
