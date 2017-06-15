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
 * Assembly sequences used here were copied from
 * PaX patch by PaX Team <pageexec@freemail.hu>
 * Being just hexadecimal constants, they are not subject to
 * any copyright.
 *
 */

#define PF_PROT		(1 << 0)
#define PF_USER		(1 << 2)
#define PF_INSTR	(1 << 4)

#ifdef CONFIG_X86_32

#include "trampolines32.h"
static inline int trampoline_emulator(struct pt_regs *regs,
				      unsigned long address)
{
	return sara_trampoline_emulator_x86_32(regs);
}

#else /* CONFIG_X86_32 */

#include "trampolines64.h"
static inline int trampoline_emulator(struct pt_regs *regs,
				      unsigned long address)
{
	return sara_trampoline_emulator_x86_64(regs, address);
}

#endif /* CONFIG_X86_32 */


int sara_trampoline_emulator(struct pt_regs *regs,
			     unsigned long error_code,
			     unsigned long address)
{
	if (!(error_code & PF_USER) ||
	    !(error_code & PF_INSTR) ||
	    !(error_code & PF_PROT))
		return 0;

	local_irq_enable();
	might_sleep();
	might_fault();
	return trampoline_emulator(regs, address);
}
