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

#ifndef __TRAMPOLINES32_H
#define __TRAMPOLINES32_H

#include <linux/printk.h>
#include <linux/uaccess.h>

struct libffi_trampoline_x86_32 {
	unsigned char mov;
	unsigned int addr1;
	unsigned char jmp;
	unsigned int addr2;
} __packed;

struct gcc_trampoline_x86_32_type1 {
	unsigned char mov1;
	unsigned int addr1;
	unsigned char mov2;
	unsigned int addr2;
	unsigned short jmp;
} __packed;

struct gcc_trampoline_x86_32_type2 {
	unsigned char mov;
	unsigned int addr1;
	unsigned char jmp;
	unsigned int addr2;
} __packed;

union trampolines_x86_32 {
	struct libffi_trampoline_x86_32 lf;
	struct gcc_trampoline_x86_32_type1 g1;
	struct gcc_trampoline_x86_32_type2 g2;
};

#define is_valid_libffi_trampoline_x86_32(UNION)	\
	(UNION.lf.mov == 0xB8 &&			\
	UNION.lf.jmp == 0xE9)

#define emulate_libffi_trampoline_x86_32(UNION, REGS) do {	\
	(REGS)->ax = UNION.lf.addr1;				\
	(REGS)->ip = (unsigned int) ((REGS)->ip +		\
				     UNION.lf.addr2 +		\
				     sizeof(UNION.lf));		\
} while (0)

#define is_valid_gcc_trampoline_x86_32_type1(UNION, REGS)	\
	(UNION.g1.mov1 == 0xB9 &&				\
	UNION.g1.mov2 == 0xB8 &&				\
	UNION.g1.jmp == 0xE0FF &&				\
	REGS->ip > REGS->sp)

#define emulate_gcc_trampoline_x86_32_type1(UNION, REGS) do {	\
	(REGS)->cx = UNION.g1.addr1;				\
	(REGS)->ax = UNION.g1.addr2;				\
	(REGS)->ip = UNION.g1.addr2;				\
} while (0)

#define is_valid_gcc_trampoline_x86_32_type2(UNION, REGS)	\
	(UNION.g2.mov == 0xB9 &&				\
	UNION.g2.jmp == 0xE9 &&					\
	REGS->ip > REGS->sp)

#define emulate_gcc_trampoline_x86_32_type2(UNION, REGS) do {	\
	(REGS)->cx = UNION.g2.addr1;				\
	(REGS)->ip = (unsigned int) ((REGS)->ip +		\
				     UNION.g2.addr2 +		\
				     sizeof(UNION.g2));		\
} while (0)

static inline int sara_trampoline_emulator_x86_32(struct pt_regs *regs)
{
	int ret;
	void __user *ip = (void __user *) regs->ip;
	union trampolines_x86_32 t;

	BUILD_BUG_ON(sizeof(t.lf) > sizeof(t.g1));
	BUILD_BUG_ON(sizeof(t.g2) > sizeof(t.lf));

	ret = copy_from_user(&t, ip, sizeof(t.g1));
	if (ret)
		ret = copy_from_user(&t, ip, sizeof(t.lf));
	if (ret)
		ret = copy_from_user(&t, ip, sizeof(t.g2));
	if (ret)
		return 0;

	if (is_valid_gcc_trampoline_x86_32_type1(t, regs)) {
		pr_debug("Trampoline: gcc1 x86_32.\n");
		emulate_gcc_trampoline_x86_32_type1(t, regs);
		return 1;
	} else if (is_valid_libffi_trampoline_x86_32(t)) {
		pr_debug("Trampoline: libffi x86_32.\n");
		emulate_libffi_trampoline_x86_32(t, regs);
		return 1;
	} else if (is_valid_gcc_trampoline_x86_32_type2(t, regs)) {
		pr_debug("Trampoline: gcc2 x86_32.\n");
		emulate_gcc_trampoline_x86_32_type2(t, regs);
		return 1;
	}

	pr_debug("Not a trampoline (x86_32).\n");

	return 0;
}

#endif /* __TRAMPOLINES32_H */
