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

#ifndef __SARA_SECURITYFS_H
#define __SARA_SECURITYFS_H

#include <linux/init.h>

#define SARA_SUBTREE_NN_LEN 24
#define SARA_CONFIG_HASH_LEN 20

struct sara_secfs_node;

int sara_secfs_init(void) __init;
int sara_secfs_subtree_register(const char *subtree_name,
				const struct sara_secfs_node *nodes,
				size_t size) __init;

enum sara_secfs_node_type {
	SARA_SECFS_BOOL,
	SARA_SECFS_READONLY_INT,
	SARA_SECFS_CONFIG_LOAD,
	SARA_SECFS_CONFIG_DUMP,
	SARA_SECFS_CONFIG_HASH,
};

struct sara_secfs_node {
	const enum sara_secfs_node_type type;
	void *const data;
	const size_t dir_contents_len;
	const char name[SARA_SUBTREE_NN_LEN];
};

struct sara_secfs_fptrs {
	int (*const load)(const char *, size_t);
	ssize_t (*const dump)(char **);
	int (*const hash)(char **);
};

struct sara_secfs_bool_flag {
	const char notice_line[SARA_SUBTREE_NN_LEN];
	bool *const flag;
};

#define DEFINE_SARA_SECFS_BOOL_FLAG(NAME, VAR)		\
const struct sara_secfs_bool_flag NAME = {		\
	.notice_line = #VAR,				\
	.flag = &VAR,					\
}

#endif /* __SARA_SECURITYFS_H */
