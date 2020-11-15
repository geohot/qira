#ifndef FLOPPY_SUBR_H
#define FLOPPY_SUBR_H

int floppy_init(void);
int floppy_read(char *dest, unsigned long offset, unsigned long length);
void floppy_fini(void);


#endif /* FLOPPY_SUBR_H */
