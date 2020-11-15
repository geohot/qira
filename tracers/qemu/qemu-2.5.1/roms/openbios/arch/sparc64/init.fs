\ va>tte-data defer MMU virtual to physical address hook for Solaris
\ We need to make sure this is in the global wordlist
active-package 0 active-package!
defer va>tte-data
0 to va>tte-data
active-package!

:noname
  ."   Type 'help' for detailed information" cr
  \ ."   boot secondary slave cdrom: " cr
  \ ."    0 >  boot hd:2,\boot\vmlinuz root=/dev/hda2" cr
  ; DIAG-initializer

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

:noname
  set-defaults
; PREPOST-initializer

\ preopen device nodes (and store the ihandles under /chosen)
:noname
  " memory" " /memory" preopen

; SYSTEM-initializer

\ use the tty interface if available
: activate-tty-interface
  " /packages/terminal-emulator" find-dev if drop
  then
;

device-end

: rmap@    ( virt -- rmentry )
  drop 0
  ;

\ Load VGA FCode driver blob
[IFDEF] CONFIG_DRIVER_VGA
  -1 value vga-driver-fcode
  " QEMU,VGA.bin" $encode-file to vga-driver-fcode
[THEN]
