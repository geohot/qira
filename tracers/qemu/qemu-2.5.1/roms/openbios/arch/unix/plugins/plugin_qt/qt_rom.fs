\ tag: Property management
\ 
\ this code implements an IEEE 1275-1994 fcode driver
\ for the OpenBIOS qt interface
\ 
\ Copyright (C) 2003 Stefan Reinauer
\ 
\ See the file "COPYING" for further information about
\ the copyright and warranty status of this work.
\ 

hex

tokenizer[ 1002 4336 0300 23 ]tokenizer ( -- vid did classid revision )

pci-revision

pci-header

fcode-version2
headers

" dev /pci" evaluate
new-device

  " ATY,QTEMU" device-name
  " display"   device-type
  
  " iso8859-1" encode-string
  " character-set" property

  true encode-int
  " iso6429-1983-colors" property

  : qt-open
    \ [..]
    ." opening framebuffer device." cr
    10 10 " pci-l@" evaluate
    /n 8 = if
      10 14 " pci-l@" evaluate
      20 << or
    then
    ." framebuffer pointer is at 0x" dup . cr
    to frame-buffer-adr
    default-font set-font
    d# 640 d# 480 d# 80 d# 30 fb8-install
    true
    ;

  : qt-close
    ." QT Interface closed." cr
    0 to frame-buffer-adr
    ;
   
  : qt-selftest
    ." QT Interface selftest" cr
    0
    ;

  ['] qt-open     is-install
  ['] qt-close    is-remove
  ['] qt-selftest is-selftest

  external

\ the following words will be defined by fb8-install
\ 
  
\  : open  ( -- true )
\    ;
  
\  : write ( addr len -- actual )
\    ;
  
\  : draw-logo ( line# addr width height -- )
\    ;
  
\  : restore ( -- )
\    ;
    
finish-device

fcode-end

pci-end
