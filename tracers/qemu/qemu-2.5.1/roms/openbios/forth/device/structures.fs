\ tag: device interface structures
\ 
\ this code implements data structures used by the
\ IEEE 1275-1994 Open Firmware Device Interface.
\ 
\ Copyright (C) 2003 Stefan Reinauer
\ 
\ See the file "COPYING" for further information about
\ the copyright and warranty status of this work.
\ 

\ this file contains the struct definitions for the following 
\ device tree structures:
\   device-node
\   active-package
\   property
\   instance


struct ( instance )
  /n field >in.instance-data            \ must go first
  /n field >in.alloced-size							\ alloced size
  /n field >in.device-node
  /n field >in.my-parent
  /n field >in.interposed
  4 cells field >in.my-unit
  2 cells field >in.arguments
  \ instance-data should be null during packet initialization
  \ this diverts access to instance variables to the dictionary
constant inst-node.size

struct ( device node )
  /n field >dn.isize                    \ instance size (must go first)
  /n field >dn.parent
  /n field >dn.child
  /n field >dn.peer
  /n field >dn.properties
  /n field >dn.methods
  /n field >dn.priv-methods
  /n field >dn.#acells
  /n field >dn.probe-addr
  inst-node.size field >dn.itemplate
constant dev-node.size

struct ( property )
  /n field >prop.next
  /n field >prop.name
  /n field >prop.addr
  /n field >prop.len
constant prop-node.size

struct ( active package )
  /n field >ap.device-str
constant active-package.size
