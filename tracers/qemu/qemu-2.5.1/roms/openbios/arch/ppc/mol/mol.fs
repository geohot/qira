

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
  " memory" " /memory" preopen
  " mmu" " /cpus/@0" preopen
  " stdout" " /packages/mol-stdout" preopen
  " stdin" " keyboard" preopen
  " nvram" " /pci/pci-bridge/mac-io/nvram" preopen
  " nvram" " /mol/nvram" preopen

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
    
: tree-fixes ( -- )
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
  " /mol/mol-tty" find-dev if drop
    " /mol/mol-tty" " input-device" $setenv
    " /mol/mol-tty" " output-device" $setenv
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
  device-end
;
