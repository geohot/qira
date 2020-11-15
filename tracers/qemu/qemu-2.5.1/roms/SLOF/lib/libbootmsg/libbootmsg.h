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
#ifndef _LIBBOOTMSG_H
#define _LIBBOOTMSG_H
void bootmsg_cp(short p);
void bootmsg_error(short p, const char *str);
void bootmsg_warning(short p, const char *str, short lvl);
void bootmsg_debugcp(short p, const char *str, short lvl);
void bootmsg_setlevel(short p, short level);
int bootmsg_checklevel(short p, short level);
void *bootmsg_nvupdate(void);
#endif /* _LIBBOOTMSG_H */
