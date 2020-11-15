\ tag: deblocker support package
\ 
\ Copyright (C) 2003 Stefan Reinauer
\ 
\ See the file "COPYING" for further information about
\ the copyright and warranty status of this work.
\ 

" /packages" find-device

\ The deblocker package makes it easy to implement byte-oriented device
\ methods, using the block-oriented or record-oriented methods defined by 
\ devices such as disks or tapes. It provides a layer of buffering between 
\ the high-level byte-oriented interface and the low-level block-oriented
\ interface. deblocker uses the max-transfer, block-size, read-blocks and
\ write-blocks methods of its parent.

new-device
  " deblocker" device-name
  \ open ( -- flag )
  \ Prepares the package for subsequent use, allocating the buffers used 
  \ by the deblocking process based upon the values returned by the parent 
  \ instance's max-transfer and block-size methods. Returns -1 if the
  \ operation succeeds, 0 otherwise.
  : open ( -- flag )

    ;

  \ close ( -- )
  \ Frees all resources that were allocated by open.
  : close ( -- )
    ;

  \ read ( adr len -- actual )
  \ Reads at most len bytes from the device into the memory buffer 
  \ beginning at adr.  Returns actual, the number of bytes actually
  \ read, or 0 if the read operation failed. Uses the parent's read-
  \ blocks method as necessary to satisfy the request, buffering any
  \ unused bytes for the next request.
  
  : read ( adr len -- actual )
    ;

  \ Writes at most len bytes from the device into the memory buffer 
  \ beginning at adr.  Returns actual, the number of bytes actually 
  \ read, or 0 if the write operation failed. Uses the parent's write-
  \ blocks method as necessary to satisfy the request, buffering any 
  \ unused bytes for the next request.
			                                  
  : write ( adr len -- actual )
    ;

  \ Sets the device position at which the next read or write will take 
  \ place. The position is specified by the 64-bit number x.position. 
  \ Returns 0 if the operation succeeds or -1 if it fails.

  : seek ( x.position -- flag )
    ;

finish-device

\ clean up afterwards
device-end
