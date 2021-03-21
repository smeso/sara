// SPDX-License-Identifier: GPL-2.0

#include "include/sara_data.h"

#ifdef CONFIG_SECURITY_SARA_WXPROT
#include <linux/cred.h>
#include <linux/lsm_hooks.h>
#include <linux/mm.h>
#include <linux/spinlock.h>

static int sara_cred_prepare(struct cred *new, const struct cred *old,
			     gfp_t gfp)
{
	*get_sara_data(new) = *get_sara_data(old);
	return 0;
}

static void sara_cred_transfer(struct cred *new, const struct cred *old)
{
	*get_sara_data(new) = *get_sara_data(old);
}

static int sara_shm_alloc_security(struct kern_ipc_perm *shp)
{
	struct sara_shm_data *d;

	d = get_sara_shm_data(shp);
	spin_lock_init(&d->lock);
	return 0;
}

static struct security_hook_list data_hooks[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(cred_prepare, sara_cred_prepare),
	LSM_HOOK_INIT(cred_transfer, sara_cred_transfer),
	LSM_HOOK_INIT(shm_alloc_security, sara_shm_alloc_security),
};

struct lsm_blob_sizes sara_blob_sizes __lsm_ro_after_init = {
	.lbs_cred = sizeof(struct sara_data),
	.lbs_ipc = sizeof(struct sara_shm_data),
};

void __init sara_data_init(void)
{
	security_add_hooks(data_hooks, ARRAY_SIZE(data_hooks), "sara");
}

#else /* CONFIG_SECURITY_SARA_WXPROT */

struct lsm_blob_sizes sara_blob_sizes __lsm_ro_after_init = { };

void __init sara_data_init(void)
{
}

#endif
