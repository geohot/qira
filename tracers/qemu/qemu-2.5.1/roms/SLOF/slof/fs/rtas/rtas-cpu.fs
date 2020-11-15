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

: rtas-start-cpu  ( pid loc r3 -- status )
   [ s" start-cpu" rtas-get-token ] LITERAL rtas-cb rtas>token l!
   3  rtas-cb rtas>nargs l!
   1  rtas-cb rtas>nret l!
   rtas-cb rtas>args2 l!
   rtas-cb rtas>args1 l!
   rtas-cb rtas>args0 l!
   0 rtas-cb rtas>args3 l!
   enter-rtas
   rtas-cb rtas>args3 l@
;
