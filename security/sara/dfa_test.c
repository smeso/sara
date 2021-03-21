// SPDX-License-Identifier: GPL-2.0

#include "include/dfa.h"
#include "include/securityfs.h"
#include <linux/lsm_hooks.h>
#include <linux/mutex.h>
#include <linux/slab.h>

#define SARA_DFA_MAX_RES_SIZE 20

struct sara_dfa_tables *table;

static DEFINE_MUTEX(test_lock);
static sara_dfa_output result;

static bool is_valid_output(sara_dfa_output output)
{
	return true;
}

static int config_load(const char *buf, size_t buf_len)
{
	struct sara_dfa_tables *dfa, *tmp;

	dfa = sara_dfa_load(buf, buf_len, is_valid_output);
	if (IS_ERR_OR_NULL(dfa)) {
		if (unlikely(dfa == NULL))
			return -EINVAL;
		else
			return PTR_ERR(dfa);
	}
	mutex_lock(&test_lock);
	tmp = table;
	table = dfa;
	mutex_unlock(&test_lock);
	sara_dfa_free_tables(tmp);
	return 0;
}

static int config_load_str(const char *buf, size_t buf_len)
{
	char *s;

	s = kmalloc(buf_len+1, GFP_KERNEL_ACCOUNT);
	if (unlikely(s == NULL))
		return -ENOMEM;
	s[buf_len] = '\0';
	memcpy(s, buf, buf_len);

	mutex_lock(&test_lock);
	result = SARA_INVALID_DFA_VALUE;
	sara_dfa_match(table, s, &result);
	mutex_unlock(&test_lock);

	kfree(s);

	return 0;
}

static ssize_t config_dump_result(char **buf)
{
	char *s;

	s = kzalloc(SARA_DFA_MAX_RES_SIZE, GFP_KERNEL_ACCOUNT);
	if (unlikely(s == NULL))
		return -ENOMEM;
	mutex_lock(&test_lock);
	if (result == SARA_INVALID_DFA_VALUE)
		snprintf(s, SARA_DFA_MAX_RES_SIZE, "%u\n", 0xffffffff);
	else
		snprintf(s,
			 SARA_DFA_MAX_RES_SIZE,
			 "%u\n",
			 (unsigned int) result);
	mutex_unlock(&test_lock);
	*buf = s;
	return strlen(s);
}

static struct sara_secfs_fptrs fptrs __lsm_ro_after_init = {
	.load = config_load,
};

static struct sara_secfs_fptrs teststr __lsm_ro_after_init = {
	.load = config_load_str,
	.dump = config_dump_result,
};

static const struct sara_secfs_node dfa_test_fs[] __initconst = {
	{
		.name = ".load",
		.type = SARA_SECFS_CONFIG_LOAD,
		.data = &fptrs,
	},
	{
		.name = "test",
		.type = SARA_SECFS_CONFIG_LOAD,
		.data = &teststr,
	},
	{
		.name = "result",
		.type = SARA_SECFS_CONFIG_DUMP,
		.data = &teststr,
	},
};

int __init sara_dfa_test_init(void)
{
	int ret;

	table = sara_dfa_make_null();
	if (unlikely(!table))
		return -ENOMEM;
	ret = sara_secfs_subtree_register("dfa_test",
					  dfa_test_fs,
					  ARRAY_SIZE(dfa_test_fs));
	if (unlikely(ret))
		goto out_fail;
	return 0;

out_fail:
	sara_dfa_free_tables(table);
	return ret;
}
