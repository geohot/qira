\ 7.4.10    Banner

defer builtin-logo
defer builtin-banner
0 value suppress-banner?

:noname
  0 0
; to builtin-logo

:noname
	builddate s"  built on " version s" Welcome to OpenBIOS v" pocket
	tmpstrcat tmpstrcat tmpstrcat drop
; to builtin-banner

: suppress-banner ( -- )
  1 to suppress-banner?
;

: banner ( -- )
  suppress-banner
  stdout @ ?dup 0= if exit then
  
  \ draw logo if stdout is a "display" node
  dup ihandle>phandle " device_type" rot get-package-property if 0 0 then
  " display" strcmp if
    drop
  else
    \ draw logo ( ihandle )
    dup ihandle>phandle " draw-logo" rot find-method if
      ( ihandle xt )
      swap >r >r
      0    \ line #
      oem-logo? if oem-logo else builtin-logo then
      ( 0 addr logo-len )
      200 = if
        d# 64 d# 64
        r> r> call-package
      else
        r> r> 2drop 2drop
      then
    else
      drop
    then
  then

  oem-banner? if oem-banner else builtin-banner then
  type cr
;
