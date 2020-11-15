\ -------------------------------------------------------------------------
\ SCSI encode/decode unit
\ -------------------------------------------------------------------------

: decode-unit-scsi ( str len -- id lun )
  ascii , left-split
  ( addr-R len-R addr-L len-L )
  parse-hex
  -rot parse-hex
  swap
;

: encode-unit-scsi ( id lun -- str len)
  swap
  pocket tohexstr
  " ," pocket tmpstrcat >r
  rot pocket tohexstr r> tmpstrcat drop
;
