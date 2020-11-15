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
//
// Copyright 2002,2003,2004  Segher Boessenkool  <segher@kernel.crashing.org>
//


#define _N(_n)		{ .n = _n },
#define _O(_n)		{ .n = CELLSIZE * (_n) },
#define _C(_c)		{ .c = _c },
#define _A(_a)		{ .a = _a },

#define ref(_xt, _nname) _A(xt_ ## _xt + _nname)
#define header(_xt, _header...) static cell xt_ ## _xt[] = { _header
#define def(_xts...) _xts };
#define lab(_xt) _A(&&code_ ## _xt)

#define DOCOL lab(DOCOL)
#define DODOES lab(DODOES)
#define DODEFER lab(DODEFER)
#define DOALIAS lab(DOALIAS)
#define DOCON lab(DOCON)
#define DOVAL lab(DOVAL)
#define DOFIELD lab(DOFIELD)
#define DOVAR lab(DOVAR)
#define DOBUFFER_X3a lab(DOBUFFER_X3a)

#define cod(_xt) def(lab(_xt))
#define col(_xt, _def...) def(DOCOL _def SEMICOLON)
#define con(_xt, _def) def(DOCON _N(_def))
#define dfr(_xt) def(DODEFER _N(0))
#define val(_xt, _def) def(DOVAL _N(_def))
#define var(_xt, _def) def(DOVAR _N(_def))


#define raw(_xt, _def) def(_def)
#define str(_xt, _def...) def(_def)
