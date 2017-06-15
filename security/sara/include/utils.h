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

#ifndef __SARA_UTILS_H
#define __SARA_UTILS_H

#include <linux/kref.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>

char *get_absolute_path(const struct path *spath, char **buf);
char *get_current_path(char **buf);

static inline void release_entry(struct kref *ref)
{
	/* All work is done after the return from kref_put(). */
}


/*
 * The following macros must be used to access S.A.R.A. configuration
 * structures.
 * They are thread-safe under the assumption that a configuration
 * won't ever be deleted but just replaced using SARA_CONFIG_REPLACE,
 * possibly using an empty configuration.
 * i.e. every call to SARA_CONFIG_PUT *must* be preceded by a matching
 * SARA_CONFIG_GET invocation.
 */

#define SARA_CONFIG_GET_RCU(DEST, CONFIG) do {	\
	rcu_read_lock();			\
	DEST = rcu_dereference(CONFIG);		\
} while (0)

#define SARA_CONFIG_PUT_RCU(DATA) do {		\
	rcu_read_unlock();			\
	DATA = NULL;				\
} while (0)

#define SARA_CONFIG_GET(DEST, CONFIG) do {				\
	rcu_read_lock();						\
	do {								\
		DEST = rcu_dereference(CONFIG);				\
	} while (DEST && !kref_get_unless_zero(&DEST->refcount));	\
	rcu_read_unlock();						\
} while (0)

#define SARA_CONFIG_PUT(DATA, FREE) do {		\
	if (kref_put(&DATA->refcount, release_entry)) {	\
		synchronize_rcu();			\
		FREE(DATA);				\
	}						\
	DATA = NULL;					\
} while (0)

#define SARA_CONFIG_REPLACE(CONFIG, NEW, FREE, LOCK) do {	\
	typeof(NEW) tmp;					\
	spin_lock(LOCK);					\
	tmp = rcu_dereference_protected(CONFIG,			\
					lockdep_is_held(LOCK));	\
	rcu_assign_pointer(CONFIG, NEW);			\
	if (kref_put(&tmp->refcount, release_entry)) {		\
		spin_unlock(LOCK);				\
		synchronize_rcu();				\
		FREE(tmp);					\
	} else							\
		spin_unlock(LOCK);				\
} while (0)

#endif /* __SARA_UTILS_H */
