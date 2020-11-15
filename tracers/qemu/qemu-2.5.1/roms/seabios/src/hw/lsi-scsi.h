#ifndef __LSI_SCSI_H
#define __LSI_SCSI_H

struct disk_op_s;
int lsi_scsi_cmd_data(struct disk_op_s *op, void *cdbcmd, u16 blocksize);
void lsi_scsi_setup(void);

#endif /* __LSI_SCSI_H */
