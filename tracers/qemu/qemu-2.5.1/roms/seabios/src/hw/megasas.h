#ifndef __MEGASAS_H
#define __MEGASAS_H

struct disk_op_s;
int megasas_cmd_data(struct disk_op_s *op, void *cdbcmd, u16 blocksize);
void megasas_setup(void);

#endif /* __MEGASAS_H */
