include config.fs

:noname 
  ."   Type 'help' for detailed information" cr
  \ ."   boot secondary slave cdrom: " cr
  \ ."    0 >  boot hd:2,\boot\vmlinuz root=/dev/hda2" cr
  ; DIAG-initializer

" /" find-device

new-device
  " memory" device-name
  \ 12230 encode-int " reg" property
  external
  : open true ;
  : close ;
  \ claim ( phys size align -- base )
  \ release ( phys size -- )
finish-device

new-device
  " cpus" device-name
  1 " #address-cells" int-property
  0 " #size-cells" int-property

  external
  : open true ;
  : close ;
  : decode-unit parse-hex ;

finish-device

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
  device-end
;
 
:noname
  set-defaults
; SYSTEM-initializer

\ preopen device nodes (and store the ihandles under /chosen)
:noname
  " memory" " /memory" preopen
  " mmu" " /cpus/@0" preopen
  " stdout" " /builtin/console" preopen
  " stdin" " /builtin/console" preopen

; SYSTEM-initializer

\ use the tty interface if available
:noname
  " /builtin/console" find-dev if drop
    " /builtin/console" " input-device" $setenv
    " /builtin/console" " output-device" $setenv
  then
; SYSTEM-initializer
	    
:noname
  " keyboard" input
; CONSOLE-IN-initializer

\ Load VGA FCode driver blob
[IFDEF] CONFIG_DRIVER_VGA
  -1 value vga-driver-fcode
  " QEMU,VGA.bin" $encode-file to vga-driver-fcode
[THEN]
