// SPDX-License-Identifier: GPL-2.0

#include <linux/bug.h>
#include <linux/kernel.h>
#include <linux/lsm_hooks.h>
#include <linux/module.h>
#include <linux/printk.h>

#include "include/sara.h"
#include "include/securityfs.h"

static const int sara_version = SARA_VERSION;

#ifdef CONFIG_SECURITY_SARA_NO_RUNTIME_ENABLE
int sara_config_locked __read_mostly = true;
#else
int sara_config_locked __read_mostly;
#endif

#ifdef CONFIG_SECURITY_SARA_DEFAULT_DISABLED
int sara_enabled __read_mostly;
#else
int sara_enabled __read_mostly = true;
#endif

static DEFINE_SARA_SECFS_BOOL_FLAG(sara_enabled_data, sara_enabled);
static DEFINE_SARA_SECFS_BOOL_FLAG(sara_config_locked_data, sara_config_locked);

static int param_set_senabled(const char *val, const struct kernel_param *kp)
{
	if (!val)
		return 0;
	if (strtobool(val, kp->arg))
		return -EINVAL;
	/* config must by locked when SARA is disabled at boot
	 * and unlocked when it's enabled
	 */
	sara_config_locked = !(*(int *) kp->arg);
	return 0;
}

static struct kernel_param_ops param_ops_senabled = {
	.set = param_set_senabled,
};

#define param_check_senabled(name, p) __param_check(name, p, int)

module_param_named(enabled, sara_enabled, senabled, 0000);
MODULE_PARM_DESC(enabled, "Disable or enable SARA at boot time. If disabled this way SARA can't be enabled again.");

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

static int __init sara_init(void)
{
	if (!sara_enabled && sara_config_locked) {
		pr_notice("permanently disabled.\n");
		return 0;
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
	return 0;

error:
	sara_enabled = false;
	sara_config_locked = true;
	pr_crit("permanently disabled.\n");
	return 1;
}

DEFINE_LSM(sara) = {
	.name = "sara",
	.enabled = &sara_enabled,
	.init = sara_init,
};
