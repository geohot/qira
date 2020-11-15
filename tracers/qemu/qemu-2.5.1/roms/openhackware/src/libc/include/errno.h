/*
 * <errno.h>
 *
 * Open Hack'Ware BIOS errno management
 * 
 * Copyright (c) 2004-2005 Jocelyn Mayer
 * 
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License V2
 *   as published by the Free Software Foundation
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#if !defined (__OHW_ERRNO_H__)
#define __OHW_ERRNO_H__

struct task {
    int errno;
};

extern struct task cur_task;

void *get_current_stack (void);

static inline int *errno_location (void)
{
    /* XXX: to fix */
#if 0
    struct task *taskp;
    
    taskp = get_current_stack();

    return &taskp->errno;
#else
    return &cur_task.errno;
#endif
}

static inline void set_errno (int errnum)
{
    *(errno_location()) = errnum;
}

static inline int get_errno (void)
{
    return *(errno_location());
}

#define errno get_errno()

enum {
    ENOMEM,
};

#endif /* !defined (__OHW_ERRNO_H__) */
