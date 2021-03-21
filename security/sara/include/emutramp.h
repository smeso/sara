/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __SARA_EMUTRAMP_H
#define __SARA_EMUTRAMP_H

#ifdef CONFIG_SECURITY_SARA_WXPROT_EMUTRAMP
int sara_trampoline_emulator(struct pt_regs *regs,
			     unsigned long error_code,
			     unsigned long address);
#else
inline int sara_trampoline_emulator(struct pt_regs *regs,
				    unsigned long error_code,
				    unsigned long address)
{
	return 0;
}
#endif /* CONFIG_SECURITY_SARA_WXPROT_EMUTRAMP */

#endif /* __SARA_EMUTRAMP_H */
