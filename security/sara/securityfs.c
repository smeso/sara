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

#include <linux/capability.h>
#include <linux/ctype.h>
#include <linux/mm.h>
#include <linux/printk.h>
#include <linux/security.h>
#include <linux/seq_file.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>

#include "include/sara.h"
#include "include/utils.h"
#include "include/securityfs.h"

#define __SARA_STR_HELPER(x) #x
#define SARA_STR(x) __SARA_STR_HELPER(x)

static struct dentry *fs_root;

static inline bool check_config_write_access(void)
{
	if (unlikely(sara_config_locked)) {
		pr_warn("config write access blocked.\n");
		return false;
	}
	return true;
}

static bool check_config_access(const struct file *file)
{
	if (!capable(CAP_MAC_ADMIN))
		return false;
	if (file->f_flags & O_WRONLY || file->f_flags & O_RDWR)
		if (unlikely(!check_config_write_access()))
			return false;
	return true;
}

static int file_flag_show(struct seq_file *seq, void *v)
{
	bool *flag = ((struct sara_secfs_bool_flag *)seq->private)->flag;

	seq_printf(seq, "%d\n", *flag);
	return 0;
}

static ssize_t file_flag_write(struct file *file,
				const char __user *ubuf,
				size_t buf_size,
				loff_t *offset)
{
	struct sara_secfs_bool_flag *bool_flag =
		((struct seq_file *) file->private_data)->private;
	char kbuf[2] = {'A', '\n'};
	bool nf;

	if (unlikely(*offset != 0))
		return -ESPIPE;

	if (unlikely(buf_size != 1 && buf_size != 2))
		return -EPERM;

	if (unlikely(copy_from_user(kbuf, ubuf, buf_size)))
		return -EFAULT;

	if (unlikely(kbuf[1] != '\n'))
		return -EPERM;

	switch (kbuf[0]) {
	case '0':
		nf = false;
		break;
	case '1':
		nf = true;
		break;
	default:
		return -EPERM;
	}

	*bool_flag->flag = nf;

	if (strlen(bool_flag->notice_line) > 0)
		pr_notice("flag \"%s\" set to %d\n",
			  bool_flag->notice_line,
			  nf);

	return buf_size;
}

static int file_flag_open(struct inode *inode, struct file *file)
{
	if (unlikely(!check_config_access(file)))
		return -EACCES;
	return single_open(file, file_flag_show, inode->i_private);
}

static const struct file_operations file_flag = {
	.owner		= THIS_MODULE,
	.open		= file_flag_open,
	.write		= file_flag_write,
	.read		= seq_read,
	.release	= single_release,
};

static int file_readonly_int_show(struct seq_file *seq, void *v)
{
	int *flag = seq->private;

	seq_printf(seq, "%d\n", *flag);
	return 0;
}

static int file_readonly_int_open(struct inode *inode, struct file *file)
{
	if (unlikely(!check_config_access(file)))
		return -EACCES;
	return single_open(file, file_readonly_int_show, inode->i_private);
}

static const struct file_operations file_readonly_int = {
	.owner		= THIS_MODULE,
	.open		= file_readonly_int_open,
	.read		= seq_read,
	.release	= single_release,
};

static ssize_t file_config_loader_write(struct file *file,
					const char __user *ubuf,
					size_t buf_size,
					loff_t *offset)
{
	const struct sara_secfs_fptrs *fptrs = file->private_data;
	char *kbuf = NULL;
	ssize_t ret;

	ret = -ESPIPE;
	if (unlikely(*offset != 0))
		goto out;

	ret = -ENOMEM;
	kbuf = kvmalloc(buf_size, GFP_KERNEL_ACCOUNT);
	if (unlikely(kbuf == NULL))
		goto out;

	ret = -EFAULT;
	if (unlikely(copy_from_user(kbuf, ubuf, buf_size)))
		goto out;

	ret = fptrs->load(kbuf, buf_size);

	if (unlikely(ret))
		goto out;

	ret = buf_size;

out:
	kvfree(kbuf);
	return ret;
}

static int file_config_loader_open(struct inode *inode, struct file *file)
{
	if (unlikely(!check_config_access(file)))
		return -EACCES;
	file->private_data = inode->i_private;
	return 0;
}

static const struct file_operations file_config_loader = {
	.owner		= THIS_MODULE,
	.open		= file_config_loader_open,
	.write		= file_config_loader_write,
};

static int file_config_show(struct seq_file *seq, void *v)
{
	const struct sara_secfs_fptrs *fptrs = seq->private;
	char *buf = NULL;
	ssize_t ret;

	ret = fptrs->dump(&buf);
	if (unlikely(ret <= 0))
		goto out;
	seq_write(seq, buf, ret);
	kvfree(buf);
	ret = 0;
out:
	return ret;
}

static int file_dumper_open(struct inode *inode, struct file *file)
{
	if (unlikely(!check_config_access(file)))
		return -EACCES;
	return single_open(file, file_config_show, inode->i_private);
}

static const struct file_operations file_config_dumper = {
	.owner		= THIS_MODULE,
	.open		= file_dumper_open,
	.read		= seq_read,
	.release	= single_release,
};

static int file_hash_show(struct seq_file *seq, void *v)
{
	const struct sara_secfs_fptrs *fptrs = seq->private;
	char *buf = NULL;
	int ret;

	ret = fptrs->hash(&buf);
	if (unlikely(ret))
		goto out;
	seq_printf(seq, "%" SARA_STR(SARA_CONFIG_HASH_LEN) "phN\n", buf);
	kvfree(buf);
	ret = 0;
out:
	return ret;
}

static int file_hash_open(struct inode *inode, struct file *file)
{
	if (unlikely(!check_config_access(file)))
		return -EACCES;
	return single_open(file, file_hash_show, inode->i_private);
}

static const struct file_operations file_hash = {
	.owner		= THIS_MODULE,
	.open		= file_hash_open,
	.read		= seq_read,
	.release	= single_release,
};

static int mk_dir(struct dentry *parent,
		const char *dir_name,
		struct dentry **dir_out)
{
	int ret = 0;

	*dir_out = securityfs_create_dir(dir_name, parent);
	if (IS_ERR(*dir_out)) {
		ret = -PTR_ERR(*dir_out);
		*dir_out = NULL;
	}
	return ret;
}

static int mk_bool_flag(struct dentry *parent,
			const char *file_name,
			struct dentry **dir_out,
			void *flag)
{
	int ret = 0;

	*dir_out = securityfs_create_file(file_name,
					0600,
					parent,
					flag,
					&file_flag);
	if (IS_ERR(*dir_out)) {
		ret = -PTR_ERR(*dir_out);
		*dir_out = NULL;
	}
	return 0;
}

static int mk_readonly_int(struct dentry *parent,
			const char *file_name,
			struct dentry **dir_out,
			void *readonly_int)
{
	int ret = 0;

	*dir_out = securityfs_create_file(file_name,
					0400,
					parent,
					readonly_int,
					&file_readonly_int);
	if (IS_ERR(*dir_out)) {
		ret = -PTR_ERR(*dir_out);
		*dir_out = NULL;
	}
	return 0;
}

static int mk_config_loader(struct dentry *parent,
			const char *file_name,
			struct dentry **dir_out,
			void *fptrs)
{
	int ret = 0;

	*dir_out = securityfs_create_file(file_name,
					0200,
					parent,
					fptrs,
					&file_config_loader);
	if (IS_ERR(*dir_out)) {
		ret = -PTR_ERR(*dir_out);
		*dir_out = NULL;
	}
	return 0;
}

static int mk_config_dumper(struct dentry *parent,
				const char *file_name,
				struct dentry **dir_out,
				void *fptrs)
{
	int ret = 0;

	*dir_out = securityfs_create_file(file_name,
					0400,
					parent,
					fptrs,
					&file_config_dumper);
	if (IS_ERR(*dir_out)) {
		ret = -PTR_ERR(*dir_out);
		*dir_out = NULL;
	}
	return 0;
}

static int mk_config_hash(struct dentry *parent,
			const char *file_name,
			struct dentry **dir_out,
			void *fptrs)
{
	int ret = 0;

	*dir_out = securityfs_create_file(file_name,
					0400,
					parent,
					fptrs,
					&file_hash);
	if (IS_ERR(*dir_out)) {
		ret = -PTR_ERR(*dir_out);
		*dir_out = NULL;
	}
	return 0;
}

struct sara_secfs_subtree {
	char name[SARA_SUBTREE_NN_LEN];
	size_t size;
	struct dentry **nodes;
	const struct sara_secfs_node *nodes_description;
	struct list_head subtree_list;
};

static LIST_HEAD(subtree_list);

int __init sara_secfs_subtree_register(const char *subtree_name,
				const struct sara_secfs_node *nodes,
				size_t size)
{
	int ret;
	struct sara_secfs_subtree *subtree = NULL;

	ret = -EINVAL;
	if (unlikely(size < 1))
		goto error;
	ret = -ENOMEM;
	subtree = kmalloc(sizeof(*subtree), GFP_KERNEL);
	if (unlikely(subtree == NULL))
		goto error;
	strncpy(subtree->name,
		subtree_name,
		sizeof(subtree->name));
	subtree->name[sizeof(subtree->name)-1] = '\0';
	subtree->size = size+1;
	subtree->nodes = kcalloc(subtree->size,
				sizeof(*subtree->nodes),
				GFP_KERNEL);
	if (unlikely(subtree->nodes == NULL))
		goto error;
	subtree->nodes_description = nodes;
	INIT_LIST_HEAD(&subtree->subtree_list);
	list_add(&subtree->subtree_list, &subtree_list);
	return 0;

error:
	kfree(subtree);
	pr_warn("SECFS: Impossible to register '%s' (%d).\n",
		subtree_name, ret);
	return ret;
}

static inline int __init create_node(enum sara_secfs_node_type type,
					struct dentry *parent,
					const char *name,
					struct dentry **output,
					void *data)
{
	switch (type) {
	case SARA_SECFS_BOOL:
		return mk_bool_flag(parent, name, output, data);
	case SARA_SECFS_READONLY_INT:
		return mk_readonly_int(parent, name, output, data);
	case SARA_SECFS_CONFIG_LOAD:
		return mk_config_loader(parent, name, output, data);
	case SARA_SECFS_CONFIG_DUMP:
		return mk_config_dumper(parent, name, output, data);
	case SARA_SECFS_CONFIG_HASH:
		return mk_config_hash(parent, name, output, data);
	default:
		return -EINVAL;
	}
}

static void subtree_unplug(struct sara_secfs_subtree *subtree)
{
	int i;

	for (i = 0; i < subtree->size; ++i) {
		if (subtree->nodes[i] != NULL) {
			securityfs_remove(subtree->nodes[i]);
			subtree->nodes[i] = NULL;
		}
	}
}

static int __init subtree_plug(struct sara_secfs_subtree *subtree)
{
	int ret;
	int i;
	const struct sara_secfs_node *nodes = subtree->nodes_description;

	ret = -EINVAL;
	if (unlikely(fs_root == NULL))
		goto out;
	ret = mk_dir(fs_root,
			subtree->name,
			&subtree->nodes[subtree->size-1]);
	if (unlikely(ret))
		goto out_unplug;
	for (i = 0; i < subtree->size-1; ++i) {
		ret = create_node(nodes[i].type,
				  subtree->nodes[subtree->size-1],
				  nodes[i].name,
				  &subtree->nodes[i],
				  nodes[i].data);
		if (unlikely(ret))
			goto out_unplug;
	}
	return 0;

out_unplug:
	subtree_unplug(subtree);
out:
	pr_warn("SECFS: Impossible to plug '%s' (%d).\n", subtree->name, ret);
	return ret;
}

static int __init subtree_plug_all(void)
{
	int ret;
	struct list_head *position;
	struct sara_secfs_subtree *subtree;

	ret = -EINVAL;
	if (unlikely(fs_root == NULL))
		goto out;
	ret = 0;
	list_for_each(position, &subtree_list) {
		subtree = list_entry(position,
					struct sara_secfs_subtree,
					subtree_list);
		if (subtree->nodes[0] == NULL) {
			ret = subtree_plug(subtree);
			if (unlikely(ret))
				goto out;
		}
	}
out:
	if (unlikely(ret))
		pr_warn("SECFS: Impossible to plug subtrees (%d).\n", ret);
	return ret;
}

static void __init subtree_free_all(bool unplug)
{
	struct list_head *position;
	struct list_head *next;
	struct sara_secfs_subtree *subtree;

	list_for_each_safe(position, next, &subtree_list) {
		subtree = list_entry(position,
					struct sara_secfs_subtree,
					subtree_list);
		list_del(position);
		if (unplug)
			subtree_unplug(subtree);
		kfree(subtree->nodes);
		kfree(subtree);
	}
}

static int mk_root(void)
{
	int ret = -1;

	if (fs_root == NULL)
		ret = mk_dir(NULL, "sara", &fs_root);
	if (unlikely(ret || fs_root == NULL))
		pr_warn("SECFS: Impossible to create root (%d).\n", ret);
	return ret;
}

static inline void rm_root(void)
{
	if (likely(fs_root != NULL)) {
		securityfs_remove(fs_root);
		fs_root = NULL;
	}
}

static inline void __init sara_secfs_destroy(void)
{
	subtree_free_all(true);
	rm_root();
}

int __init sara_secfs_init(void)
{
	int ret;

	if (!sara_enabled && sara_config_locked)
		return 0;

	fs_root = NULL;

	ret = mk_root();
	if (unlikely(ret))
		goto error;

	ret = subtree_plug_all();
	if (unlikely(ret))
		goto error;

	subtree_free_all(false);

	pr_debug("securityfs initilaized.\n");
	return 0;

error:
	sara_secfs_destroy();
	pr_crit("impossible to build securityfs.\n");
	return ret;
}

fs_initcall(sara_secfs_init);
