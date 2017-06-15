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
 * Assembly sequences used here were copied from
 * PaX patch by PaX Team <pageexec@freemail.hu>
 * Being just hexadecimal constants, they are not subject to
 * any copyright.
 *
 */

#ifndef __EMUTRAMP_H
#define __EMUTRAMP_H

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

#endif /* __EMUTRAMP_H */
