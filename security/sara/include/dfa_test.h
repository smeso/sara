/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __SARA_DFA_TEST_H
#define __SARA_DFA_TEST_H

#ifdef CONFIG_SECURITY_SARA_DFA_TEST

#include <linux/init.h>
int sara_dfa_test_init(void) __init;

#else /* CONFIG_SECURITY_SARA_DFA_TEST */
inline int sara_dfa_test_init(void)
{
	return 0;
}
#endif /* CONFIG_SECURITY_SARA_DFA_TEST */

#endif /* __SARA_DFA_TEST_H */
