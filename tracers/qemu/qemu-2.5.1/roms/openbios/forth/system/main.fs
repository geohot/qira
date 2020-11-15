\ tag: misc useful functions
\ 
\ Open Firmware Startup
\ 
\ Copyright (C) 2003 Samuel Rydh
\ 
\ See the file "COPYING" for further information about
\ the copyright and warranty status of this work.
\ 

variable PREPOST-list
variable POST-list
variable SYSTEM-list
variable DIAG-list

: PREPOST-initializer ( xt -- )
  PREPOST-list list-add ,
;

: POST-initializer ( xt -- )
  POST-list list-add ,
;

: SYSTEM-initializer ( xt -- )
  SYSTEM-list list-add ,
;

: DIAG-initializer ( xt -- )
  DIAG-list list-add ,
;


\ OpenFirmware entrypoint
: initialize-of ( startmem endmem -- )
  initialize-forth

  PREPOST-list begin list-get while @ execute repeat
  POST-list begin list-get while @ execute repeat
  SYSTEM-list begin list-get while @ execute repeat

  \ evaluate nvramrc script
  use-nvramrc? if
    nvramrc evaluate
  then

  \ probe-all etc.
  suppress-banner? 0= if
    probe-all
    install-console
    banner
  then

  DIAG-list begin list-get while @ execute repeat

  auto-boot? if
    boot-command evaluate
  then

  outer-interpreter
;
