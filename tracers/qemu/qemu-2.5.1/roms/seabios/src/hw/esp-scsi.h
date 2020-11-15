#ifndef __ESP_SCSI_H
#define __ESP_SCSI_H

struct disk_op_s;
int esp_scsi_cmd_data(struct disk_op_s *op, void *cdbcmd, u16 blocksize);
void esp_scsi_setup(void);

#endif /* __ESP_SCSI_H */
