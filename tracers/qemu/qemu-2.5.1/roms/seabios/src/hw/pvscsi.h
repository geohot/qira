#ifndef _PVSCSI_H_
#define _PVSCSI_H_

struct disk_op_s;
int pvscsi_cmd_data(struct disk_op_s *op, void *cdbcmd, u16 blocksize);
void pvscsi_setup(void);

#endif /* _PVSCSI_H_ */
