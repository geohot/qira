/******************************************************************************
 * Copyright (c) 2004, 2008 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/
#ifndef TERMCTRL_H
#define TERMCTRL_H

/* foreground colors */
#define TERM_FG_BLACK    "[30m"
#define TERM_FG_RED      "[31m"
#define TERM_FG_GREEN    "[32m"
#define TERM_FG_YELLOW   "[33m"
#define TERM_FG_BLUE     "[34m"
#define TERM_FG_MAGENTA  "[35m"
#define TERM_FG_CYAN     "[36m"
#define TERM_FG_WHITE    "[37m"

/* background colors */
#define TERM_BG_BLACK    "[40m"
#define TERM_BG_RED      "[41m"
#define TERM_BG_GREEN    "[42m"
#define TERM_BG_YELLOW   "[43m"
#define TERM_BG_BLUE     "[44m"
#define TERM_BG_MAGENTA  "[45m"
#define TERM_BG_CYAN     "[46m"
#define TERM_BG_WHITE    "[47m"

/* control */
#define TERM_CTRL_RESET      "[0m"
#define TERM_CTRL_BRIGHT     "[1m"
#define TERM_CTRL_DIM        "[2m"
#define TERM_CTRL_UNDERSCORE "[3m"
#define TERM_CTRL_BLINK      "[4m"
#define TERM_CTRL_REVERSE    "[5m"
#define TERM_CTRL_HIDDEN     "[6m"
#define TERM_CTRL_CLEAR      "[2J"
#define TERM_CTRL_HOME       "[H"

#define TERM_CTRL_1UP        "[1A"
#define TERM_CTRL_1BACK      "[1D"
#define TERM_CTRL_SAVECRS    "[s"
#define TERM_CTRL_RESTCRS    "[u"
#define TERM_CTRL_CRSON      "[?25h"
#define TERM_CTRL_CRSOFF     "[?25l"
#define TERM_CTRL_CRSFWDN    "[%dC"
#define TERM_CTRL_CRSX       "[%dC"
#define TERM_CTRL_CRSY       "[%dB"
#define TERM_CTRL_CRSXY      "[%d;%dH" /* y,x */

/* keys */
#define KEY_CTRL 0x1b
#define KEY_UP   0x41
#define KEY_DN   0x42

#endif
