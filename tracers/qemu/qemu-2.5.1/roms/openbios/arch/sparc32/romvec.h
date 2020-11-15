/*
 * romvec main C function and handler declarations
 */

extern volatile uint32_t *obp_ticks;
void *init_openprom(void);

int obp_devopen(char *str);
int obp_devopen_handler(char *str);
int obp_devclose(int dev_desc);
int obp_devclose_handler(int dev_desc);
int obp_rdblkdev(int dev_desc, int num_blks, int offset, char *buf);
int obp_rdblkdev_handler(int dev_desc, int num_blks, int offset, char *buf);
int obp_nbgetchar(void);
int obp_nbgetchar_handler(void);
int obp_nbputchar(int ch);
int obp_nbputchar_handler(int ch);
void obp_putstr(char *str, int len);
void obp_putstr_handler(char *str, int len);
void obp_printf(__const__ char *fmt, ...);
void obp_printf_handler(__const__ char *fmt, ...);
void obp_reboot(char *str);
void obp_reboot_handler(char *str);
void obp_abort(void);
void obp_abort_handler(void);
void obp_halt(void);
void obp_halt_handler(void);
void obp_fortheval_v2(char *str, int arg0, int arg1, int arg2, int arg3, int arg4);
void obp_fortheval_v2_handler(char *str, int arg0, int arg1, int arg2, int arg3, int arg4);
int obp_inst2pkg(int dev_desc);
int obp_inst2pkg_handler(int dev_desc);
char *obp_dumb_memalloc(char *va, unsigned int size);
char *obp_dumb_memalloc_handler(char *va, unsigned int size);
void obp_dumb_memfree(char *va, unsigned size);
void obp_dumb_memfree_handler(char *va, unsigned size);
char *obp_dumb_mmap(char *va, int which_io, unsigned int pa, unsigned int size);
char *obp_dumb_mmap_handler(char *va, int which_io, unsigned int pa, unsigned int size);
void obp_dumb_munmap(__attribute__((unused)) char *va, __attribute__((unused)) unsigned int size);
void obp_dumb_munmap_handler(__attribute__((unused)) char *va, __attribute__((unused)) unsigned int size);
int obp_devread(int dev_desc, char *buf, int nbytes);
int obp_devread_handler(int dev_desc, char *buf, int nbytes);
int obp_devwrite(int dev_desc, char *buf, int nbytes);
int obp_devwrite_handler(int dev_desc, char *buf, int nbytes);
int obp_devseek(int dev_desc, int hi, int lo);
int obp_devseek_handler(int dev_desc, int hi, int lo);
int obp_cpustart(__attribute__((unused))unsigned int whichcpu,
                        __attribute__((unused))int ctxtbl_ptr,
                        __attribute__((unused))int thiscontext,
                        __attribute__((unused))char *prog_counter);
int obp_cpustart_handler(__attribute__((unused))unsigned int whichcpu,
                        __attribute__((unused))int ctxtbl_ptr,
                        __attribute__((unused))int thiscontext,
                        __attribute__((unused))char *prog_counter);
int obp_cpustop(__attribute__((unused)) unsigned int whichcpu);
int obp_cpustop_handler(__attribute__((unused)) unsigned int whichcpu);
int obp_cpuidle(__attribute__((unused)) unsigned int whichcpu);
int obp_cpuidle_handler(__attribute__((unused)) unsigned int whichcpu);
int obp_cpuresume(__attribute__((unused)) unsigned int whichcpu);
int obp_cpuresume_handler(__attribute__((unused)) unsigned int whichcpu);
int obp_nextnode(int node);
int obp_nextnode_handler(int node);
int obp_child(int node);
int obp_child_handler(int node);
int obp_proplen(int node, const char *name);
int obp_proplen_handler(int node, const char *name);
int obp_getprop(int node, const char *name, char *value);
int obp_getprop_handler(int node, const char *name, char *value);
int obp_setprop(__attribute__((unused)) int node,
                       __attribute__((unused)) const char *name,
		       __attribute__((unused)) char *value,
		       __attribute__((unused)) int len);
int obp_setprop_handler(__attribute__((unused)) int node,
                       __attribute__((unused)) const char *name,
		       __attribute__((unused)) char *value,
		       __attribute__((unused)) int len);
const char *obp_nextprop(int node, const char *name);
const char *obp_nextprop_handler(int node, const char *name);
char *obp_memalloc(char *va, unsigned int size, unsigned int align);
char *obp_memalloc_handler(char *va, unsigned int size, unsigned int align);
