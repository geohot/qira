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


s" filler" device-name

: block-size  s" block-size" $call-parent ;
: seek        s" seek"       $call-parent ;
: read        s" read"       $call-parent ;

: open  true ;
: close ;
