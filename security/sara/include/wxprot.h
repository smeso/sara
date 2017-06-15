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

#ifndef __SARA_WXPROT_H
#define __SARA_WXPROT_H

#ifdef CONFIG_SECURITY_SARA_WXPROT

#include <linux/init.h>
int sara_wxprot_init(void) __init;

#else /* CONFIG_SECURITY_SARA_WXPROT */
inline int sara_wxprot_init(void)
{
	return 0;
}
#endif /* CONFIG_SECURITY_SARA_WXPROT */

#endif /* __SARA_WXPROT_H */
