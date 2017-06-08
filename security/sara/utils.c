// SPDX-License-Identifier: GPL-2.0

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

#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

#include "include/sara.h"
#include "include/utils.h"

/**
 * get_absolute_path - return the absolute path for a struct path
 * @spath: the struct path to report
 * @buf: double pointer where the newly allocated buffer will be placed
 *
 * Returns a pointer into @buf or an error code.
 *
 * The caller MUST kvfree @buf when finished using it.
 */
char *get_absolute_path(const struct path *spath, char **buf)
{
	size_t size = 128;
	char *work_buf = NULL;
	char *path = NULL;

	do {
		kvfree(work_buf);
		work_buf = NULL;
		if (size > SARA_PATH_MAX) {
			path = ERR_PTR(-ENAMETOOLONG);
			goto error;
		}
		work_buf = sara_kvmalloc(size);
		if (unlikely(work_buf == NULL)) {
			path = ERR_PTR(-ENOMEM);
			goto error;
		}
		path = d_absolute_path(spath, work_buf, size);
		size *= 2;
	} while (PTR_ERR(path) == -ENAMETOOLONG);
	if (!IS_ERR(path))
		goto out;

error:
	kvfree(work_buf);
	work_buf = NULL;
out:
	*buf = work_buf;
	return path;
}

/**
 * get_current_path - return the absolute path for the exe_file
 *		      in the current task_struct, falling back
 *		      to the contents of the comm field.
 * @buf: double pointer where the newly allocated buffer will be placed
 *
 * Returns a pointer into @buf or an error code.
 *
 * The caller MUST kvfree @buf when finished using it.
 */
char *get_current_path(char **buf)
{
	struct file *exe_file;
	char *path = NULL;

	exe_file = get_task_exe_file(current);
	if (exe_file) {
		path = get_absolute_path(&exe_file->f_path, buf);
		fput(exe_file);
	}
	if (IS_ERR_OR_NULL(path)) {
		*buf = kzalloc(TASK_COMM_LEN, GFP_KERNEL);
		__get_task_comm(*buf, TASK_COMM_LEN, current);
		path = *buf;
	}
	return path;
}

/**
 * sara_kvmalloc - do allocation preferring kmalloc but falling back to vmalloc
 * @size: how many bytes of memory are required
 *
 * Return: allocated buffer or NULL if failed
 *
 * It is possible that ruleset being loaded from the user is larger than
 * what can be allocated by kmalloc, in those cases fall back to vmalloc.
 *
 * Nearly identical copy of AppArmor's __aa_kvmalloc.
 */
void *__attribute__((malloc)) sara_kvmalloc(size_t size)
{
	void *buffer = NULL;

	__might_sleep(__FILE__, __LINE__, 0);

	if (size == 0)
		return NULL;

	/* do not attempt kmalloc if we need more than 16 pages at once */
	if (size <= (16*PAGE_SIZE))
		buffer = kmalloc(size, GFP_KERNEL | __GFP_NORETRY |
				 __GFP_NOWARN);
	if (!buffer)
		buffer = vmalloc(size);

	return buffer;
}

/**
 * sara_kvcalloc - do allocation preferring kcalloc but falling back to vmalloc
 * @size: number of object to allocate
 * @size: how many bytes of memory are required per each object
 *
 * Return: allocated buffer or NULL if failed
 *
 * It is possible that ruleset being loaded from the user is larger than
 * what can be allocated by kcalloc, in those cases fall back to vmalloc.
 *
 * Nearly identical copy of AppArmor's __aa_kvmalloc.
 */
void *__attribute__((malloc)) sara_kvcalloc(size_t n, size_t size)
{
	void *buffer = NULL;

	__might_sleep(__FILE__, __LINE__, 0);

	if (size == 0)
		return NULL;

	/* do not attempt kmalloc if we need more than 16 pages at once */
	if (size <= (16*PAGE_SIZE))
		buffer = kcalloc(n, size, GFP_KERNEL | __GFP_NORETRY |
				 __GFP_NOWARN);
	if (!buffer)
		buffer = vzalloc(n*size);

	return buffer;
}
