/* SPDX-License-Identifier: GPL-2.0 */

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
