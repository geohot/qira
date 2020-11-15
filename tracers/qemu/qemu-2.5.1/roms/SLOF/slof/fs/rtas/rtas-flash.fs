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

: rtas-ibm-update-flash-64-and-reboot  ( block-list -- status )
   [ s" ibm,update-flash-64-and-reboot" rtas-get-token ] LITERAL rtas-cb rtas>token l!
   1 rtas-cb rtas>nargs l!
   1 rtas-cb rtas>nret l!
   rtas-cb rtas>args0 l!
   enter-rtas
   rtas-cb rtas>args1 l@
;

: rtas-ibm-manage-flash-image  ( image-to-commit -- status )
   [ s" ibm,manage-flash-image" rtas-get-token ] LITERAL rtas-cb rtas>token l!
   1 rtas-cb rtas>nargs l!
   1 rtas-cb rtas>nret l!
   rtas-cb rtas>args0 l!
   enter-rtas
   rtas-cb rtas>args1 l@
;

: rtas-set-flashside  ( flashside -- status )
   [ s" rtas-set-flashside" rtas-get-token ] LITERAL rtas-cb rtas>token l!
   1 rtas-cb rtas>nargs l!
   1 rtas-cb rtas>nret l!
   rtas-cb rtas>args0 l!
   enter-rtas
   rtas-cb rtas>args1 l@
;

: rtas-get-flashside  ( -- status )
   [ s" rtas-get-flashside" rtas-get-token ] LITERAL rtas-cb rtas>token l!
   0 rtas-cb rtas>nargs l!
   1 rtas-cb rtas>nret l!
   enter-rtas
   rtas-cb rtas>args0 l@
;
