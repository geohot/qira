:noname 
  ."   Type 'help' for detailed information" cr
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
  device-end
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

dev /

\ node suitable for non-PCI devices 
new-device
  " unix" device-name
	0 encode-int " #address-cells" property
	0 encode-int " #size-cells" property
	
	external
  : open true ;
  : close ;

\ block device node
new-device
  " block" device-name
  " unix-block" device-type
	1 " #address-cells" int-property
	0 " #size-cells" int-property
	
	external
  : open true ;
  : close ;
  : decode-unit parse-hex ;

\ testnode
\ new-device
\   " kappa" device-name
\ 
\   1 encode-int " reg" property
\   external
\   : open true ;
\   : close ;
\ finish-device

finish-device
finish-device

dev /aliases
" /unix/block/disk" encode-string " hd" property

device-end
