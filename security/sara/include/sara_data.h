/* SPDX-License-Identifier: GPL-2.0 */

/*
 * S.A.R.A. Linux Security Module
 *
 * Copyright (C) 2017 Salvatore Mesoraca <s.mesoraca16@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 *
 */

#ifndef __SARA_DATA_H
#define __SARA_DATA_H

#include <linux/fs.h>
#include <linux/init.h>
#include <linux/spinlock.h>

int sara_data_init(void) __init;

#ifdef CONFIG_SECURITY_SARA_WXPROT

struct sara_data {
	unsigned long	relro_page;
	struct file	*relro_file;
	u16		wxp_flags;
	u16		execve_flags;
	bool		relro_page_found;
	bool		mmap_blocked;
};

struct sara_shm_data {
	bool		no_exec;
	bool		no_write;
	spinlock_t	lock;
};

struct sara_inode_data {
	struct task_struct *task;
};

#define get_sara_data_leftvalue(X) ((X)->security_sara)
#define get_sara_data(X) ((struct sara_data *) (X)->security_sara)
#define get_current_sara_data() get_sara_data(current_cred())

#define get_sara_wxp_flags(X) (get_sara_data((X))->wxp_flags)
#define get_current_sara_wxp_flags() get_sara_wxp_flags(current_cred())

#define get_sara_execve_flags(X) (get_sara_data((X))->execve_flags)
#define get_current_sara_execve_flags() get_sara_execve_flags(current_cred())

#define get_sara_relro_page(X) (get_sara_data((X))->relro_page)
#define get_current_sara_relro_page() get_sara_relro_page(current_cred())

#define get_sara_relro_file(X) (get_sara_data((X))->relro_file)
#define get_current_sara_relro_file() get_sara_relro_file(current_cred())

#define get_sara_relro_page_found(X) (get_sara_data((X))->relro_page_found)
#define get_current_sara_relro_page_found() \
	get_sara_relro_page_found(current_cred())

#define get_sara_mmap_blocked(X) (get_sara_data((X))->mmap_blocked)
#define get_current_sara_mmap_blocked() get_sara_mmap_blocked(current_cred())

#define get_sara_shm_data(X) ((struct sara_shm_data *) (X)->security_sara)
#define get_sara_shm_no_exec(X) (get_sara_shm_data((X))->no_exec)
#define get_sara_shm_no_write(X) (get_sara_shm_data((X))->no_write)
#define lock_sara_shm(X) (spin_lock(&get_sara_shm_data((X))->lock))
#define unlock_sara_shm(X) (spin_unlock(&get_sara_shm_data((X))->lock))

#define get_sara_inode_data(X) ((struct sara_inode_data *) (X)->security_sara)
#define get_sara_inode_task(X) (get_sara_inode_data((X))->task)

#endif

#endif /* __SARA_H */
