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

#ifndef __SARA_TRAMPOLINES64_H
#define __SARA_TRAMPOLINES64_H

#include <linux/printk.h>
#include <linux/uaccess.h>

#include "trampolines32.h"

struct libffi_trampoline_x86_64 {
	unsigned short mov1;
	unsigned long addr1;
	unsigned short mov2;
	unsigned long addr2;
	unsigned char stcclc;
	unsigned short jmp1;
	unsigned char jmp2;
} __packed;

struct gcc_trampoline_x86_64_type1 {
	unsigned short mov1;
	unsigned long addr1;
	unsigned short mov2;
	unsigned long addr2;
	unsigned short jmp1;
	unsigned char jmp2;
} __packed;

struct gcc_trampoline_x86_64_type2 {
	unsigned short mov1;
	unsigned int addr1;
	unsigned short mov2;
	unsigned long addr2;
	unsigned short jmp1;
	unsigned char jmp2;
} __packed;

union trampolines_x86_64 {
	struct libffi_trampoline_x86_64 lf;
	struct gcc_trampoline_x86_64_type1 g1;
	struct gcc_trampoline_x86_64_type2 g2;
};

static inline int is_libffi_tramp_x86_64(const union trampolines_x86_64 *u)
{
	return (u->lf.mov1 == 0xBB49 &&
		u->lf.mov2 == 0xBA49 &&
		(u->lf.stcclc == 0xF8 ||
		 u->lf.stcclc == 0xF9) &&
		u->lf.jmp1 == 0xFF49 &&
		u->lf.jmp2 == 0xE3);
}

static inline void emu_libffi_tramp_x86_64(const union trampolines_x86_64 *u,
					   struct pt_regs *regs)
{
	regs->r11 = u->lf.addr1;
	regs->r10 = u->lf.addr2;
	regs->ip = u->lf.addr1;
	if (u->lf.stcclc == 0xF8)
		regs->flags &= ~X86_EFLAGS_CF;
	else
		regs->flags |= X86_EFLAGS_CF;
}

static inline int is_gcc_tramp_x86_64_t1(const union trampolines_x86_64 *u,
					 const struct pt_regs *regs)
{
	return (u->g1.mov1 == 0xBB49 &&
		u->g1.mov2 == 0xBA49 &&
		u->g1.jmp1 == 0xFF49 &&
		u->g1.jmp2 == 0xE3 &&
		regs->ip > regs->sp);
}

static inline void emu_gcc_tramp_x86_64_t1(const union trampolines_x86_64 *u,
					   struct pt_regs *regs)
{
	regs->r11 = u->g1.addr1;
	regs->r10 = u->g1.addr2;
	regs->ip = u->g1.addr1;
}

static inline int is_gcc_tramp_x86_64_t2(const union trampolines_x86_64 *u,
					 const struct pt_regs *regs)
{
	return (u->g2.mov1 == 0xBB41 &&
		u->g2.mov2 == 0xBA49 &&
		u->g2.jmp1 == 0xFF49 &&
		u->g2.jmp2 == 0xE3 &&
		regs->ip > regs->sp);
}

static inline void emu_gcc_tramp_x86_64_t2(const union trampolines_x86_64 *u,
					   struct pt_regs *regs)
{
	regs->r11 = u->g2.addr1;
	regs->r10 = u->g2.addr2;
	regs->ip = u->g2.addr1;
}

static inline int sara_trampoline_emulator_x86_64(struct pt_regs *regs,
						  unsigned long address)
{
	int ret;
	void __user *ip = (void __user *) regs->ip;
	union trampolines_x86_64 t;

	BUILD_BUG_ON(sizeof(t.g1) > sizeof(t.lf));
	BUILD_BUG_ON(sizeof(t.g2) > sizeof(t.g1));

	if (regs->cs == __USER32_CS ||
	    regs->cs & (1<<2)) {
		if (address >> 32)	/* K8 erratum #100 */
			return 0;
		return sara_trampoline_emulator_x86_32(regs);
	}

	ret = copy_from_user(&t, ip, sizeof(t.lf));
	if (ret)
		ret = copy_from_user(&t, ip, sizeof(t.g1));
	if (ret)
		ret = copy_from_user(&t, ip, sizeof(t.g2));
	if (ret)
		return 0;

	if (is_libffi_tramp_x86_64(&t)) {
		pr_debug("Trampoline: libffi x86_64.\n");
		emu_libffi_tramp_x86_64(&t, regs);
		return 1;
	} else if (is_gcc_tramp_x86_64_t1(&t, regs)) {
		pr_debug("Trampoline: gcc1 x86_64.\n");
		emu_gcc_tramp_x86_64_t1(&t, regs);
		return 1;
	} else if (is_gcc_tramp_x86_64_t2(&t, regs)) {
		pr_debug("Trampoline: gcc2 x86_64.\n");
		emu_gcc_tramp_x86_64_t2(&t, regs);
		return 1;
	}

	pr_debug("Not a trampoline (x86_64).\n");

	return 0;

}

#endif /* __SARA_TRAMPOLINES64_H */
