new-device

VALUE sudev
s" slofdev.fs" included
sudev slof-dev>port l@ dup set-unit encode-phys " reg" property
sudev slof-dev>udev @ VALUE udev

s" usb-mouse" device-name

\ .S cr
\     dup slof-dev>udev dup . @ . cr
\     dup slof-dev>port dup . l@ . cr
\     dup slof-dev>devaddr dup . l@ . cr
\     dup slof-dev>hcitype dup . l@ . cr
\     dup slof-dev>num dup . l@ . cr
\     dup slof-dev>devtype dup . l@ . cr

."     USB mouse " cr

finish-device
