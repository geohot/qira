#ifndef VIDEO_VGA_H
#define VIDEO_VGA_H

/* drivers/vga_load_regs.c */
void vga_load_regs(void);

/* drivers/vga_set_mode.c */
void vga_set_gmode (void);
void vga_set_amode (void);
void vga_font_load(unsigned char *vidmem, const unsigned char *font, int height, int num_chars);

/* drivers/vga_vbe.c */
void vga_set_color(int i, unsigned int r, unsigned int g, unsigned int b);
void vga_vbe_set_mode(int width, int height, int depth);
void vga_vbe_init(const char *path, unsigned long fb, uint32_t fb_size,
                  unsigned long rom, uint32_t rom_size);

extern volatile uint32_t *dac;

#endif /* VIDEO_VGA_H */
