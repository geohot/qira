\   briq specific initialization code
\ 
\   Copyright (C) 2004 Greg Watson
\ 
\   This program is free software; you can redistribute it and/or
\   modify it under the terms of the GNU General Public License
\   as published by the Free Software Foundation
\ 


\ -------------------------------------------------------------------------
\ initialization
\ -------------------------------------------------------------------------

: make-openable ( path )
  find-dev if
    begin ?dup while
      \ install trivial open and close methods
      dup active-package! is-open
      parent
    repeat
  then
;

: preopen ( chosen-str node-path )
  2dup make-openable
  
  " /chosen" find-device
  open-dev ?dup if
    encode-int 2swap property
  else
    2drop
  then
;

\ preopen device nodes (and store the ihandles under /chosen)
:noname
  " rtc" " /pci/isa/rtc" preopen
  " memory" " /memory" preopen
  " mmu" " /cpu@0" preopen
  " stdout" " /packages/terminal-emulator" preopen
  " stdin" " keyboard" preopen

; SYSTEM-initializer


\ -------------------------------------------------------------------------
\ device tree fixing
\ -------------------------------------------------------------------------

\ add decode-address methods
: (make-decodable) ( phandle -- )

    dup " #address-cells" rot get-package-property 0= if
      decode-int nip nip
      over " decode-unit" rot find-method if 2drop else
        ( save phandle ncells )
      
        over active-package!
        case
          1 of ['] parse-hex " decode-unit" is-xt-func endof
          3 of
            " bus-range" active-package get-package-property 0= if
              decode-int nip nip
              ['] encode-unit-pci " encode-unit" is-xt-func
              " decode-unit" is-func-begin
                ['] (lit) , ,
                ['] decode-unit-pci-bus ,
              is-func-end
            then
          endof
        endcase
      then
    then
    drop
;
    
: init-briq-tree ( -- )
  active-package
  
  iterate-tree-begin
  begin ?dup while

    dup (make-decodable)
    
    iterate-tree
  repeat

  active-package!
;

\ use the tty interface if available
: activate-tty-interface
  " /packages/terminal-emulator" find-dev if drop
    " /packages/terminal-emulator" " input-device" $setenv
    " /packages/terminal-emulator" " output-device" $setenv
  then
;

:noname
  " keyboard" input
; CONSOLE-IN-initializer


\ -------------------------------------------------------------------------
\ pre-booting
\ -------------------------------------------------------------------------

: update-chosen
  " /chosen" find-device
  stdin @ encode-int " stdin" property
  stdout @ encode-int " stdout" property
  " /pci/isa/interrupt-controller" find-dev if encode-int " interrupt-controller" property then
  device-end
;
