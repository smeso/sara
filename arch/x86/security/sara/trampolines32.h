/* SPDX-License-Identifier: GPL-2.0 */

/*
 * SARA Linux Security Module
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

#ifndef __SARA_TRAMPOLINES32_H
#define __SARA_TRAMPOLINES32_H

#include <linux/printk.h>
#include <linux/uaccess.h>

struct libffi_trampoline_x86_32 {
	unsigned char mov;
	unsigned int addr1;
	unsigned char jmp;
	unsigned int addr2;
} __packed;

struct gcc_trampoline_x86_32_t1 {
	unsigned char mov1;
	unsigned int addr1;
	unsigned char mov2;
	unsigned int addr2;
	unsigned short jmp;
} __packed;

struct gcc_trampoline_x86_32_t2 {
	unsigned char mov;
	unsigned int addr1;
	unsigned char jmp;
	unsigned int addr2;
} __packed;

union trampolines_x86_32 {
	struct libffi_trampoline_x86_32 lf;
	struct gcc_trampoline_x86_32_t1 g1;
	struct gcc_trampoline_x86_32_t2 g2;
};

static inline int is_libffi_tramp_x86_32(const union trampolines_x86_32 *u)
{
	return (u->lf.mov == 0xB8 && u->lf.jmp == 0xE9);
}

static inline void emu_libffi_tramp_x86_32(const union trampolines_x86_32 *u,
					   struct pt_regs *regs)
{
	regs->ax = u->lf.addr1;
	regs->ip = (unsigned int) (regs->ip +
				   u->lf.addr2 +
				   sizeof(u->lf));
}

static inline int is_gcc_tramp_x86_32_t1(const union trampolines_x86_32 *u,
					 const struct pt_regs *regs)
{
	return (u->g1.mov1 == 0xB9 &&
		u->g1.mov2 == 0xB8 &&
		u->g1.jmp == 0xE0FF &&
		regs->ip > regs->sp);
}

static inline void emu_gcc_tramp_x86_32_t1(const union trampolines_x86_32 *u,
					   struct pt_regs *regs)
{
	regs->cx = u->g1.addr1;
	regs->ax = u->g1.addr2;
	regs->ip = u->g1.addr2;
}

static inline int is_gcc_tramp_x86_32_t2(const union trampolines_x86_32 *u,
					 const struct pt_regs *regs)
{
	return (u->g2.mov == 0xB9 &&
		u->g2.jmp == 0xE9 &&
		regs->ip > regs->sp);
}

static inline void emu_gcc_tramp_x86_32_t2(const union trampolines_x86_32 *u,
					   struct pt_regs *regs)
{
	regs->cx = u->g2.addr1;
	regs->ip = (unsigned int) (regs->ip +
				   u->g2.addr2 +
				   sizeof(u->g2));
}

static inline int sara_trampoline_emulator_x86_32(struct pt_regs *regs)
{
	int ret;
	void __user *ip = (void __user *) regs->ip;
	union trampolines_x86_32 t; //zero init

	BUILD_BUG_ON(sizeof(t.lf) > sizeof(t.g1));
	BUILD_BUG_ON(sizeof(t.g2) > sizeof(t.lf));

	ret = copy_from_user(&t, ip, sizeof(t.g1));
	if (ret)
		ret = copy_from_user(&t, ip, sizeof(t.lf));
	if (ret)
		ret = copy_from_user(&t, ip, sizeof(t.g2));
	if (ret)
		return 0;

	if (is_gcc_tramp_x86_32_t1(&t, regs)) {
		pr_debug("Trampoline: gcc1 x86_32.\n");
		emu_gcc_tramp_x86_32_t1(&t, regs);
		return 1;
	} else if (is_libffi_tramp_x86_32(&t)) {
		pr_debug("Trampoline: libffi x86_32.\n");
		emu_libffi_tramp_x86_32(&t, regs);
		return 1;
	} else if (is_gcc_tramp_x86_32_t2(&t, regs)) {
		pr_debug("Trampoline: gcc2 x86_32.\n");
		emu_gcc_tramp_x86_32_t2(&t, regs);
		return 1;
	}

	pr_debug("Not a trampoline (x86_32).\n");

	return 0;
}

#endif /* __SARA_TRAMPOLINES32_H */
