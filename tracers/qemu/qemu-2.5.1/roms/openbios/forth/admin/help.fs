\ tag: firmware help
\ 
\ this code implements IEEE 1275-1994 ch. 7.4.1
\ 
\ Copyright (C) 2003 Stefan Reinauer
\ 
\ See the file "COPYING" for further information about
\ the copyright and warranty status of this work.
\ 

hex 

: (help-generic)
  ." Enter 'help command-name' or 'help category-name' for more help" cr
  ." (Use ONLY the first word of a category description)" cr
  ." Examples: help select -or- help line" cr cr
  ." Categories:" cr
  ."   boot (Load and execute a client program)" cr
  ."   diag (Diagnostic routines)" cr
  ;

: (help-diag)
  ." test <device>  Run the selftest method for specified device" cr
  ." test-all       Execute test for all devices using selftest method" cr
  ;
  
: (help-boot)
  ." boot [<device-specifier>:<device-arguments>] [boot-arguments]" cr
  ." Examples:" cr
  ." boot             Default boot (values specified in nvram variables)" cr
  ." boot disk1:a     Boot from disk1 partition a" cr
  ." boot hd:1,\boot\vmlinuz root=/dev/hda1" cr
  ;
  
: help ( "{name}<cr>" -- )
  \ Provide information for category or specific command.
  linefeed parse cr
  dup 0= if 
    (help-generic)
    2drop
  else
    2dup " diag" rot min comp not if
      (help-diag) 2drop exit
    then
    2dup " boot" rot min comp not if
      (help-boot) 2drop exit
    then
    ." No help available for " type cr
  then
  ;
  
