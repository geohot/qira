\ *****************************************************************************
\ * Copyright (c) 2004, 2008 IBM Corporation
\ * All rights reserved.
\ * This program and the accompanying materials
\ * are made available under the terms of the BSD License
\ * which accompanies this distribution, and is available at
\ * http://www.opensource.org/licenses/bsd-license.php
\ *
\ * Contributors:
\ *     IBM Corporation - initial implementation
\ ****************************************************************************/

: rtas-power-off   ( x y -- status )
   [ s" power-off" rtas-get-token ] LITERAL rtas-cb rtas>token l!
   2 rtas-cb rtas>nargs l!
   1 rtas-cb rtas>nret l!
   rtas-cb rtas>args0 l!
   rtas-cb rtas>args1 l!
   enter-rtas
   rtas-cb rtas>args2 l@
;

: power-off  ( -- )  0 0 rtas-power-off ;


: rtas-system-reboot  ( -- status )
   [ s" system-reboot" rtas-get-token ] LITERAL rtas-cb rtas>token l!
   0 rtas-cb rtas>nargs l!
   1 rtas-cb rtas>nret l!
   rtas-cb rtas>args0 l!
   enter-rtas
   rtas-cb rtas>args1 l@
;
