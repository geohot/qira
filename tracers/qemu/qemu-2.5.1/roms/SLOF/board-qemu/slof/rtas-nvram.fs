\ *****************************************************************************
\ * Copyright (c) 2012 IBM Corporation
\ * All rights reserved.
\ * This program and the accompanying materials
\ * are made available under the terms of the BSD License
\ * which accompanies this distribution, and is available at
\ * http://www.opensource.org/licenses/bsd-license.php
\ *
\ * Contributors:
\ *     IBM Corporation - initial implementation
\ ****************************************************************************/

." Populating " pwd cr

0 VALUE my-nvram-fetch
0 VALUE my-nvram-store
0 VALUE my-nvram-size
0 VALUE nvram-addr

: open true ;
: close ;

: write ( adr len -- actual )
  nip
;

: read  ( adr len -- actual )
  nip
;

: setup-alias
    " nvram" find-alias 0= IF
        " nvram" get-node node>path set-alias
    ELSE
        drop
    THEN
;

" #bytes" get-node get-package-property 0= IF
    decode-int to my-nvram-size 2drop
    " nvram-fetch" rtas-get-token to my-nvram-fetch
    " nvram-store" rtas-get-token to my-nvram-store
    my-nvram-size to nvram-size
    nvram-size alloc-mem to nvram-addr
    my-nvram-fetch my-nvram-store nvram-size nvram-addr internal-nvram-init
THEN

setup-alias
