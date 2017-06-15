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

#include "include/sara_data.h"

#ifdef CONFIG_SECURITY_SARA_WXPROT
#include <linux/cred.h>
#include <linux/lsm_hooks.h>
#include <linux/mm.h>
#include <linux/spinlock.h>

static int sara_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
	struct sara_data *d;

	d = kzalloc(sizeof(*d), gfp);
	if (d == NULL)
		return -ENOMEM;
	get_sara_data_leftvalue(cred) = d;
	return 0;
}

static void sara_cred_free(struct cred *cred)
{
	struct sara_data *d;

	d = get_sara_data(cred);
	if (d != NULL) {
		kfree(d);
		get_sara_data_leftvalue(cred) = NULL;
	}
}

static int sara_cred_prepare(struct cred *new, const struct cred *old,
			     gfp_t gfp)
{
	struct sara_data *d;

	d = kmemdup(get_sara_data(old), sizeof(*d), gfp);
	if (d == NULL)
		return -ENOMEM;
	get_sara_data_leftvalue(new) = d;
	return 0;
}

static void sara_cred_transfer(struct cred *new, const struct cred *old)
{
	*get_sara_data(new) = *get_sara_data(old);
}

static int sara_shm_alloc_security(struct kern_ipc_perm *shp)
{
	struct sara_shm_data *d;

	d = kzalloc(sizeof(*d), GFP_KERNEL);
	if (d == NULL)
		return -ENOMEM;
	spin_lock_init(&d->lock);
	get_sara_data_leftvalue(shp) = d;
	return 0;
}

static void sara_shm_free_security(struct kern_ipc_perm *shp)
{
	kfree(get_sara_data_leftvalue(shp));
}

static struct security_hook_list data_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(cred_alloc_blank, sara_cred_alloc_blank),
	LSM_HOOK_INIT(cred_free, sara_cred_free),
	LSM_HOOK_INIT(cred_prepare, sara_cred_prepare),
	LSM_HOOK_INIT(cred_transfer, sara_cred_transfer),
	LSM_HOOK_INIT(shm_alloc_security, sara_shm_alloc_security),
	LSM_HOOK_INIT(shm_free_security, sara_shm_free_security),
};

int __init sara_data_init(void)
{
	security_add_hooks(data_hooks, ARRAY_SIZE(data_hooks), "sara");
	return sara_cred_alloc_blank((struct cred *) current->real_cred,
				     GFP_KERNEL);
}

#else /* CONFIG_SECURITY_SARA_WXPROT */

int __init sara_data_init(void)
{
	return 0;
}

#endif
