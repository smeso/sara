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

#include <linux/bug.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/module.h>

#include "include/sara.h"
#include "include/securityfs.h"

static const int sara_version = SARA_VERSION;

#ifdef CONFIG_SECURITY_SARA_NO_RUNTIME_ENABLE
bool sara_config_locked __read_mostly = true;
#else
bool sara_config_locked __read_mostly;
#endif

#ifdef CONFIG_SECURITY_SARA_DEFAULT_DISABLED
bool sara_enabled __read_mostly;
#else
bool sara_enabled __read_mostly = true;
#endif

static DEFINE_SARA_SECFS_BOOL_FLAG(sara_enabled_data, sara_enabled);
static DEFINE_SARA_SECFS_BOOL_FLAG(sara_config_locked_data, sara_config_locked);

static int param_set_senabled(const char *val, const struct kernel_param *kp)
{
	if (!val)
		return 0;
	if (strtobool(val, kp->arg))
		return -EINVAL;
	/* config must by locked when S.A.R.A. is disabled at boot
	 * and unlocked when it's enabled
	 */
	sara_config_locked = !(*(bool *) kp->arg);
	return 0;
}

static struct kernel_param_ops param_ops_senabled = {
	.set = param_set_senabled,
};

#define param_check_senabled(name, p) __param_check(name, p, bool)

module_param_named(enabled, sara_enabled, senabled, 0000);
MODULE_PARM_DESC(enabled, "Disable or enable S.A.R.A. at boot time. If disabled this way S.A.R.A. can't be enabled again.");

static const struct sara_secfs_node main_fs[] __initconst = {
	{
		.name = "enabled",
		.type = SARA_SECFS_BOOL,
		.data = (void *) &sara_enabled_data,
	},
	{
		.name = "locked",
		.type = SARA_SECFS_BOOL,
		.data = (void *) &sara_config_locked_data,
	},
	{
		.name = "version",
		.type = SARA_SECFS_READONLY_INT,
		.data = (int *) &sara_version,
	},
};

void __init sara_init(void)
{
	if (!sara_enabled && sara_config_locked) {
		pr_notice("permanently disabled.\n");
		return;
	}

	pr_debug("initializing...\n");

	if (sara_secfs_subtree_register("main",
					main_fs,
					ARRAY_SIZE(main_fs))) {
		pr_crit("impossible to register main fs.\n");
		goto error;
	}

	pr_debug("initialized.\n");

	if (sara_enabled)
		pr_info("enabled\n");
	else
		pr_notice("disabled\n");
	return;

error:
	sara_enabled = false;
	sara_config_locked = true;
	pr_crit("permanently disabled.\n");
}
