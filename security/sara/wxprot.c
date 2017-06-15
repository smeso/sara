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
 */

#ifdef CONFIG_SECURITY_SARA_WXPROT

#include <linux/binfmts.h>
#include <linux/cred.h>
#include <linux/elf.h>
#include <linux/kref.h>
#include <linux/lsm_hooks.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/ratelimit.h>
#include <linux/spinlock.h>

#include "include/sara.h"
#include "include/sara_data.h"
#include "include/utils.h"
#include "include/securityfs.h"
#include "include/wxprot.h"

#define SARA_WXPROT_CONFIG_VERSION 0

#define SARA_WXP_HEAP		0x0001
#define SARA_WXP_STACK		0x0002
#define SARA_WXP_OTHER		0x0004
#define SARA_WXP_WXORX		0x0008
#define SARA_WXP_COMPLAIN	0x0010
#define SARA_WXP_VERBOSE	0x0020
#define SARA_WXP_MMAP		0x0040
#define SARA_WXP_TRANSFER	0x0200
#define SARA_WXP_NONE		0x0000
#define SARA_WXP_MPROTECT	(SARA_WXP_HEAP	| \
				 SARA_WXP_STACK	| \
				 SARA_WXP_OTHER)
#define __SARA_WXP_ALL		(SARA_WXP_MPROTECT	| \
				 SARA_WXP_MMAP		| \
				 SARA_WXP_WXORX		| \
				 SARA_WXP_COMPLAIN	| \
				 SARA_WXP_VERBOSE)
#define SARA_WXP_ALL		__SARA_WXP_ALL

struct wxprot_rule {
	char *path;
	u16 flags;
	bool exact;
};

struct wxprot_config_container {
	u32 rules_size;
	struct wxprot_rule *rules;
	size_t buf_len;
	struct kref refcount;
	char hash[SARA_CONFIG_HASH_LEN];
};

static struct wxprot_config_container __rcu *wxprot_config;

static const int wxprot_config_version = SARA_WXPROT_CONFIG_VERSION;
static bool wxprot_enabled __read_mostly = true;
static DEFINE_SPINLOCK(wxprot_config_lock);

static u16 default_flags __ro_after_init =
				CONFIG_SECURITY_SARA_WXPROT_DEFAULT_FLAGS;

static const bool wxprot_emutramp;

static void pr_wxp(char *msg)
{
	char *buf, *path;

	path = get_current_path(&buf);
	pr_notice_ratelimited("WXP: %s in '%s' (%d).\n",
			      msg, path, current->pid);
	kvfree(buf);
}

/**
 * are_flags_valid - check whether the given combination of flags is valid
 * @flags: the flags to be checked
 *
 * Returns true if flags are valid, false otherwise.
 *
 * Rules checked:
 *   - Unused bits must be set to 0.
 *   - Any feature in the "MPROTECT" group require "WXORX".
 *   - "COMPLAIN" and "VERBOSE" can only be used if some other feature is
 *     enabled.
 *   - Trampoline emulation can only be used when all "MPROTECT"
 *     features are active.
 *   - "MMAP" protection requires SARA_WXP_OTHER
 */
static bool are_flags_valid(u16 flags)
{
	flags &= ~SARA_WXP_TRANSFER;
	if (unlikely((flags & SARA_WXP_ALL) != flags))
		return false;
	if (unlikely(flags & SARA_WXP_MPROTECT &&
		     !(flags & SARA_WXP_WXORX)))
		return false;
	if (unlikely(flags & (SARA_WXP_COMPLAIN | SARA_WXP_VERBOSE) &&
		     !(flags & (SARA_WXP_MPROTECT |
				SARA_WXP_WXORX |
				SARA_WXP_MMAP))))
		return false;
	if (unlikely(flags & SARA_WXP_MMAP &&
		     !(flags & SARA_WXP_OTHER)))
		return false;
	return true;
}

module_param(wxprot_enabled, bool, 0);
MODULE_PARM_DESC(wxprot_enabled,
		 "Disable or enable S.A.R.A. WX Protection at boot time.");

static int param_set_wxpflags(const char *val, const struct kernel_param *kp)
{
	u16 flags;

	if (!val || kstrtou16(val, 0, &flags) != 0 || !are_flags_valid(flags))
		return -EINVAL;
	*(u16 *) kp->arg = flags;
	return 0;
}

static struct kernel_param_ops param_ops_wxpflags = {
	.set = param_set_wxpflags,
};

#define param_check_wxpflags(name, p) __param_check(name, p, u16)

module_param_named(wxprot_default_flags, default_flags, wxpflags, 0);
MODULE_PARM_DESC(wxprot_default_flags,
		 "Disable or enable S.A.R.A. WX Protection at boot time.");

/*
 * MMAP exec restriction
 */
#define PT_GNU_RELRO (PT_LOOS + 0x474e552)

union elfh {
	struct elf32_hdr c32;
	struct elf64_hdr c64;
};

union elfp {
	struct elf32_phdr c32;
	struct elf64_phdr c64;
};

#define find_relro_section(ELFH, ELFP, FILE, RELRO, FOUND) do {		\
	unsigned long i;						\
	int _tmp;							\
	loff_t _pos = 0;						\
	if (ELFH.e_type == ET_DYN || ELFH.e_type == ET_EXEC) {		\
		for (i = 0; i < ELFH.e_phnum; ++i) {			\
			_pos = ELFH.e_phoff + i*sizeof(ELFP);		\
			_tmp = kernel_read(FILE, &ELFP, sizeof(ELFP),	\
					   &_pos);			\
			if (_tmp != sizeof(ELFP))			\
				break;					\
			if (ELFP.p_type == PT_GNU_RELRO) {		\
				RELRO = ELFP.p_offset >> PAGE_SHIFT;	\
				FOUND = true;				\
				break;					\
			}						\
		}							\
	}								\
} while (0)

static int set_relro_page(struct linux_binprm *bprm)
{
	union elfh elf_h;
	union elfp elf_p;
	unsigned long relro_page = 0;
	bool relro_page_found = false;
	int ret;
	loff_t pos = 0;

	ret = kernel_read(bprm->file, &elf_h, sizeof(elf_h), &pos);
	if (ret == sizeof(elf_h) &&
	    strncmp(elf_h.c32.e_ident, ELFMAG, SELFMAG) == 0) {
		if (elf_h.c32.e_ident[EI_CLASS] == ELFCLASS32) {
			find_relro_section(elf_h.c32,
					   elf_p.c32,
					   bprm->file,
					   relro_page,
					   relro_page_found);
		} else if (IS_ENABLED(CONFIG_64BIT) &&
			   elf_h.c64.e_ident[EI_CLASS] == ELFCLASS64) {
			find_relro_section(elf_h.c64,
					   elf_p.c64,
					   bprm->file,
					   relro_page,
					   relro_page_found);
		}
	} else
		return 2; /* It isn't an ELF */

	if (relro_page_found) {
		get_sara_relro_page(bprm->cred) = relro_page;
		get_sara_relro_page_found(bprm->cred) = relro_page_found;
		get_sara_relro_file(bprm->cred) = bprm->file;
		return 0;
	} else
		return 1; /* It's an ELF without a RELRO section */
}

static inline int is_relro_page(const struct vm_area_struct *vma)
{
	if (get_current_sara_relro_page_found() &&
	    get_current_sara_relro_page() == vma->vm_pgoff &&
	    get_current_sara_relro_file() == vma->vm_file)
		return 1;
	return 0;
}

/*
 * LSM hooks
 */
static int sara_bprm_set_creds(struct linux_binprm *bprm)
{
	int i;
	struct wxprot_config_container *c;
	u16 sara_wxp_flags = default_flags;
	char *buf = NULL;
	char *path = NULL;
	struct cred *current_new;

	sara_wxp_flags = get_sara_wxp_flags(bprm->cred);
	get_sara_mmap_blocked(bprm->cred) = false;
	get_sara_relro_page_found(bprm->cred) = false;
	get_sara_relro_page(bprm->cred) = 0;
	get_sara_relro_file(bprm->cred) = NULL;
	get_sara_wxp_flags(bprm->cred) = SARA_WXP_NONE;
	get_sara_execve_flags(bprm->cred) = SARA_WXP_NONE;

	if (!sara_enabled || !wxprot_enabled)
		return 0;

	/*
	 * SARA_WXP_TRANSFER means that the parent
	 * wants this child to inherit its flags.
	 */
	if (!(sara_wxp_flags & SARA_WXP_TRANSFER)) {
		sara_wxp_flags = default_flags;
		path = get_absolute_path(&bprm->file->f_path, &buf);
		if (IS_ERR(path)) {
			path = (char *) bprm->interp;
			if (PTR_ERR(path) == -ENAMETOOLONG)
				pr_warn_ratelimited("WXP: path too long for '%s'. Default flags will be used.\n",
						path);
			else
				pr_warn_ratelimited("WXP: can't find path for '%s'. Default flags will be used.\n",
						path);
			goto skip_flags;
		}
		SARA_CONFIG_GET_RCU(c, wxprot_config);
		for (i = 0; i < c->rules_size; ++i) {
			if ((c->rules[i].exact &&
			     strcmp(c->rules[i].path, path) == 0) ||
			    (!c->rules[i].exact &&
			     strncmp(c->rules[i].path, path,
				     strlen(c->rules[i].path)) == 0)) {
				sara_wxp_flags = c->rules[i].flags;
				/* most specific path always come first */
				break;
			}
		}
		SARA_CONFIG_PUT_RCU(c);
	} else
		path = (char *) bprm->interp;

	if (sara_wxp_flags != default_flags &&
	    sara_wxp_flags & SARA_WXP_VERBOSE)
		pr_debug_ratelimited("WXP: '%s' run with flags '0x%x'.\n",
				     path, sara_wxp_flags);

skip_flags:
	i = set_relro_page(bprm);
	/*
	 * i != 0 means no relro segment
	 * i == 1 means the file wasn't an ELF
	 *
	 * We want to disable SARA_WXP_MMAP when the file is missing
	 * the RELRO segment.
	 * We want to verbosely report this case only if the file
	 * was an ELF.
	 *
	 */
	if (i != 0) {
		if (sara_wxp_flags & SARA_WXP_VERBOSE &&
		    sara_wxp_flags & SARA_WXP_MMAP &&
		    i == 1)
			pr_notice_ratelimited("WXP: failed to find RELRO section in '%s'.\n",
					      path);
		sara_wxp_flags &= ~SARA_WXP_MMAP;
	}
	kvfree(buf);
	get_sara_wxp_flags(bprm->cred) = sara_wxp_flags;

	/*
	 * Set the flags to be used for validation
	 * during the execve and discard SARA_WXP_MMAP:
	 * it doesn't make sense to prevent executable
	 * mmap during execve.
	 */
	current_new = prepare_creds();
	if (unlikely(current_new == NULL))
		return -ENOMEM;
	get_sara_execve_flags(current_new) = sara_wxp_flags & ~SARA_WXP_MMAP;
	commit_creds(current_new);

	return 0;
}

#define sara_warn_or_return(err, msg) do {		\
	if ((sara_wxp_flags & SARA_WXP_VERBOSE))	\
		pr_wxp(msg);				\
	if (!(sara_wxp_flags & SARA_WXP_COMPLAIN))	\
		return -err;				\
} while (0)

#define sara_warn_or_goto(label, msg) do {		\
	if ((sara_wxp_flags & SARA_WXP_VERBOSE))	\
		pr_wxp(msg);				\
	if (!(sara_wxp_flags & SARA_WXP_COMPLAIN))	\
		goto label;				\
} while (0)

static int sara_check_vmflags(vm_flags_t vm_flags)
{
	u16 sara_wxp_flags;

	if (!sara_enabled || !wxprot_enabled)
		return 0;

	/*
	 * Memory allocations done during an execve should be
	 * checked against the rules of the new executable,
	 * instead of those of the current one.
	 */
	if (current->in_execve)
		sara_wxp_flags = get_current_sara_execve_flags();
	else
		sara_wxp_flags = get_current_sara_wxp_flags();

	/*
	 * Be quiet when using security_check_vmflags to decide
	 * what to do with a PT_GNU_STACK header
	 */
	if (current->in_execve && vm_flags == (VM_EXEC|VM_READ|VM_WRITE))
		sara_wxp_flags &= ~SARA_WXP_VERBOSE;

	/*
	 * If "W xor X" is active for the current thread
	 * this function must not allow new allocations that
	 * have both the VM_WRITE and the VM_EXEC flags.
	 */
	if (unlikely(sara_wxp_flags & SARA_WXP_WXORX &&
		     vm_flags & VM_WRITE &&
		     vm_flags & VM_EXEC))
		sara_warn_or_return(EPERM, "W^X");
	/*
	 * When the "MMAP" protection is on and shared libraries have
	 * been already loaded (i.e. get_current_sara_mmap_blocked
	 * returns true), this function must not allow:
	 *    - new executable allocations
	 *    - new non-executable allocations that may become
	 *      executable bypassing the "MPROTECT" restriction;
	 *      the "MPROTECT" protection will prevent a non-executable
	 *      area to became executable only if it has the
	 *      "VM_MAYWRITE" flag on.
	 */
	if (unlikely(sara_wxp_flags & SARA_WXP_MMAP &&
		     (vm_flags & VM_EXEC ||
		      (!(vm_flags & VM_MAYWRITE) && (vm_flags & VM_MAYEXEC))) &&
		     get_current_sara_mmap_blocked()))
		sara_warn_or_return(EPERM, "executable mmap");

	return 0;
}

static int sara_shm_shmat(struct kern_ipc_perm *shp,
			  char __user *shmaddr,
			  int shmflg)
{
	int block = 0;
	u16 sara_wxp_flags;
	char buf[TASK_COMM_LEN];

	if (!sara_enabled || !wxprot_enabled)
		return 0;

	sara_wxp_flags = get_current_sara_wxp_flags();

	/*
	 * Allow executable mappings if and only if this shm
	 * was never attached as writable.
	 *
	 * Allow writable mappings if and only if this shm
	 * was never attached as executable.
	 *
	 * We don't need to handle the case in which this
	 * shm is attached as both writable and executable:
	 * sara_check_vmflags takes care of that.
	 */
	if (sara_wxp_flags & SARA_WXP_OTHER) {
		if (shmflg & SHM_EXEC && shmflg & SHM_RDONLY) {
			lock_sara_shm(shp);
			if (unlikely(get_sara_shm_no_exec(shp)))
				block = 1;
			else
				get_sara_shm_no_write(shp) = true;
			unlock_sara_shm(shp);
		} else if (!(shmflg & (SHM_EXEC | SHM_RDONLY))) {
			lock_sara_shm(shp);
			if (unlikely(get_sara_shm_no_write(shp)))
				block = 2;
			else
				get_sara_shm_no_exec(shp) = true;
			unlock_sara_shm(shp);
		}
	}

	if ((sara_wxp_flags & SARA_WXP_VERBOSE)) {
		if (unlikely(block)) {
			get_task_comm(buf, current);
			if (block == 1)
				pr_notice_ratelimited("WXP: executable SHM in '%s' (%d).\n",
						      buf, current->pid);
			else if (block == 2)
				pr_notice_ratelimited("WXP: writable SHM in '%s' (%d).\n",
						      buf, current->pid);
		}
	}
	if (unlikely(block) && !(sara_wxp_flags & SARA_WXP_COMPLAIN))
		return -EACCES;
	return 0;
}

static int sara_file_mprotect(struct vm_area_struct *vma,
				unsigned long reqprot,
				unsigned long prot)
{
	u16 sara_wxp_flags;

	if (!sara_enabled || !wxprot_enabled)
		return 0;

	if (current->in_execve)
		sara_wxp_flags = get_current_sara_execve_flags();
	else
		sara_wxp_flags = get_current_sara_wxp_flags();

	/*
	 * vmas that may have been writable at some time in the past
	 * (i.e. have the VM_MAYWRITE flag on) shouldn't be allowed
	 * to be marked executable, unless they already are.
	 */
	if (unlikely(sara_wxp_flags & SARA_WXP_MPROTECT &&
		     prot & PROT_EXEC &&
		     !(vma->vm_flags & VM_EXEC) &&
		     vma->vm_flags & VM_MAYWRITE)) {
		/*
		 * If every MPROTECT flag is on and verbose reporting
		 * isn't needed, skip checking where the vma points to.
		 * Otherwise check if it points to a file mapping,
		 * to heap, to stack or to anywhere else.
		 */
		if ((sara_wxp_flags & SARA_WXP_MPROTECT) == SARA_WXP_MPROTECT &&
		    !(sara_wxp_flags & SARA_WXP_COMPLAIN) &&
		    !(sara_wxp_flags & SARA_WXP_VERBOSE))
			return -EACCES;
		else if (vma->vm_file) {
			if (sara_wxp_flags & SARA_WXP_OTHER)
				sara_warn_or_return(EACCES,
						    "mprotect on file mmap");
		} else if (vma->vm_start >= vma->vm_mm->start_brk &&
			vma->vm_end <= vma->vm_mm->brk) {
			if (sara_wxp_flags & SARA_WXP_HEAP)
				sara_warn_or_return(EACCES,
						    "mprotect on heap");
		} else if ((vma->vm_start <= vma->vm_mm->start_stack &&
			    vma->vm_end >= vma->vm_mm->start_stack) ||
			   vma_is_stack_for_current(vma)) {
			if (sara_wxp_flags & SARA_WXP_STACK)
				sara_warn_or_return(EACCES,
						    "mprotect on stack");
		} else if (sara_wxp_flags & SARA_WXP_OTHER)
			sara_warn_or_return(EACCES,
					    "mprotect on anon mmap");
	}

	/*
	 * If "W xor X" is active for the current thread
	 * VM_EXEC and VM_WRITE can't be turned on at
	 * the same time, unless they already are.
	 */
	if (unlikely(sara_wxp_flags & SARA_WXP_WXORX &&
		     prot & PROT_EXEC &&
		     prot & PROT_WRITE &&
		     (!(vma->vm_flags & VM_EXEC) ||
		      !(vma->vm_flags & VM_WRITE))))
		sara_warn_or_return(EACCES, "W^X");

	/*
	 * If the dynamic loader marks the "relro section" as
	 * read-only then it has finished loading shared libraries
	 * and, if the SARA_WXP_MMAP flag is on, new executable
	 * mmaps will be blocked from now on.
	 */
	if (unlikely(vma->vm_flags & VM_WRITE &&
		     !(prot & PROT_WRITE) &&
		     is_relro_page(vma)))
		get_current_sara_mmap_blocked() = true;

	return 0;
}

static struct security_hook_list wxprot_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(bprm_set_creds, sara_bprm_set_creds),
	LSM_HOOK_INIT(check_vmflags, sara_check_vmflags),
	LSM_HOOK_INIT(shm_shmat, sara_shm_shmat),
	LSM_HOOK_INIT(file_mprotect, sara_file_mprotect),
};

struct binary_config_header {
	char magic[8];
	__le32 version;
	__le32 rules_size;
	char hash[SARA_CONFIG_HASH_LEN];
} __packed;

struct binary_config_rule {
	__le16 path_len;
	__le16 flags;
	u8 exact;
} __packed;

static void config_free(struct wxprot_config_container *data)
{
	int i;

	for (i = 0; i < data->rules_size; ++i)
		kfree(data->rules[i].path);
	kvfree(data->rules);
	kfree(data);
}

static int config_load(const char *buf, size_t buf_len)
{
	int ret;
	int i, j;
	int path_len;
	size_t inc;
	size_t last_path_len = SARA_PATH_MAX;
	bool last_exact = true;
	const char *pos;
	struct wxprot_config_container *new;
	struct binary_config_header *h;
	struct binary_config_rule *r;

	ret = -EINVAL;
	if (unlikely(buf_len < sizeof(*h)))
		goto out;

	h = (struct binary_config_header *) buf;
	pos = buf + sizeof(*h);

	ret = -EINVAL;
	if (unlikely(memcmp(h->magic, "SARAWXPR", 8) != 0))
		goto out;
	if (unlikely(le32_to_cpu(h->version) != wxprot_config_version))
		goto out;

	ret = -ENOMEM;
	new = kmalloc(sizeof(*new), GFP_KERNEL);
	if (unlikely(new == NULL))
		goto out;
	kref_init(&new->refcount);
	new->rules_size = le32_to_cpu(h->rules_size);
	BUILD_BUG_ON(sizeof(new->hash) != sizeof(h->hash));
	memcpy(new->hash, h->hash, sizeof(new->hash));
	if (unlikely(new->rules_size == 0)) {
		new->rules = NULL;
		goto replace;
	}

	ret = -ENOMEM;
	new->rules = kvmalloc_array(new->rules_size,
				    sizeof(*new->rules),
				    GFP_KERNEL | __GFP_ZERO);

	if (unlikely(new->rules == NULL))
		goto out_new;
	for (i = 0; i < new->rules_size; ++i) {
		r = (struct binary_config_rule *) pos;
		pos += sizeof(*r);
		inc = pos-buf;
		path_len = le16_to_cpu(r->path_len);
		new->rules[i].flags = le16_to_cpu(r->flags);
		new->rules[i].exact = r->exact;

		ret = -EINVAL;
		if (unlikely(inc + path_len > buf_len))
			goto out_rules;
		if (unlikely(path_len > last_path_len))
			goto out_rules;
		if (unlikely((int) new->rules[i].exact != 0 &&
			     (int) new->rules[i].exact != 1))
			goto out_rules;
		if (unlikely(path_len == last_path_len &&
			     new->rules[i].exact &&
			     !last_exact))
			goto out_rules;
		if (!are_flags_valid(new->rules[i].flags))
			goto out_rules;
		if (path_len > 0) {
			if (pos[0] != '/')
				goto out_rules;
			for (j = 0; j < path_len - 1; ++j) {
				if (pos[j] == '/' &&
				pos[j+1] == '/')
					goto out_rules;
				if (j + 2 < path_len &&
				pos[j] == '/' &&
				pos[j+1] == '.' &&
				pos[j+2] == '/')
					goto out_rules;
				if (j + 3 < path_len &&
				pos[j] == '/' &&
				pos[j+1] == '.' &&
				pos[j+2] == '.' &&
				pos[j+3] == '/')
					goto out_rules;
			}
		}

		ret = -ENOMEM;
		new->rules[i].path = kmalloc(path_len+1, GFP_KERNEL);
		if (unlikely(new->rules[i].path == NULL))
			goto out_rules;
		memcpy(new->rules[i].path, pos, path_len);
		new->rules[i].path[path_len] = '\0';
		if (i > 0 &&
		    unlikely(new->rules[i].exact == new->rules[i-1].exact &&
			     strcmp(new->rules[i].path,
				    new->rules[i-1].path) == 0))
			goto out_rules;
		pos += path_len;
		last_path_len = path_len;
		last_exact = new->rules[i].exact;
	}
	new->buf_len = (size_t) (pos-buf);

replace:
	SARA_CONFIG_REPLACE(wxprot_config,
			    new,
			    config_free,
			    &wxprot_config_lock);
	pr_notice("WXP: new rules loaded.\n");
	return 0;

out_rules:
	for (i = 0; i < new->rules_size; ++i)
		kfree(new->rules[i].path);
	kvfree(new->rules);
out_new:
	kfree(new);
out:
	pr_notice("WXP: failed to load rules.\n");
	return ret;
}

static ssize_t config_dump(char **buf)
{
	int i;
	ssize_t ret;
	size_t buf_len;
	char *pos;
	char *mybuf;
	u16 path_len;
	int rulen;
	struct wxprot_config_container *c;
	struct wxprot_rule *rc;
	struct binary_config_header *h;
	struct binary_config_rule *r;

	ret = -ENOMEM;
	SARA_CONFIG_GET(c, wxprot_config);
	buf_len = c->buf_len;
	mybuf = kvmalloc(buf_len, GFP_KERNEL_ACCOUNT);
	if (unlikely(mybuf == NULL))
		goto out;
	rulen = c->rules_size;
	h = (struct binary_config_header *) mybuf;
	memcpy(h->magic, "SARAWXPR", 8);
	h->version = cpu_to_le32(SARA_WXPROT_CONFIG_VERSION);
	h->rules_size = cpu_to_le32(rulen);
	BUILD_BUG_ON(sizeof(c->hash) != sizeof(h->hash));
	memcpy(h->hash, c->hash, sizeof(h->hash));
	pos = mybuf + sizeof(*h);
	for (i = 0; i < rulen; ++i) {
		r = (struct binary_config_rule *) pos;
		pos += sizeof(*r);
		if (buf_len < (pos - mybuf))
			goto out;
		rc = &c->rules[i];
		r->flags = cpu_to_le16(rc->flags);
		r->exact = (u8) rc->exact;
		path_len = strlen(rc->path);
		r->path_len = cpu_to_le16(path_len);
		if (buf_len < ((pos - mybuf) + path_len))
			goto out;
		memcpy(pos, rc->path, path_len);
		pos += path_len;
	}
	ret = (ssize_t) (pos - mybuf);
	*buf = mybuf;
out:
	SARA_CONFIG_PUT(c, config_free);
	return ret;
}

static int config_hash(char **buf)
{
	int ret;
	struct wxprot_config_container *config;

	ret = -ENOMEM;
	*buf = kzalloc(sizeof(config->hash), GFP_KERNEL);
	if (unlikely(*buf == NULL))
		goto out;

	SARA_CONFIG_GET_RCU(config, wxprot_config);
	memcpy(*buf, config->hash, sizeof(config->hash));
	SARA_CONFIG_PUT_RCU(config);

	ret = 0;
out:
	return ret;
}

static DEFINE_SARA_SECFS_BOOL_FLAG(wxprot_enabled_data,
				   wxprot_enabled);

static struct sara_secfs_fptrs fptrs __ro_after_init = {
	.load = config_load,
	.dump = config_dump,
	.hash = config_hash,
};

static const struct sara_secfs_node wxprot_fs[] __initconst = {
	{
		.name = "enabled",
		.type = SARA_SECFS_BOOL,
		.data = (void *) &wxprot_enabled_data,
	},
	{
		.name = "version",
		.type = SARA_SECFS_READONLY_INT,
		.data = (int *) &wxprot_config_version,
	},
	{
		.name = "default_flags",
		.type = SARA_SECFS_READONLY_INT,
		.data = &default_flags,
	},
	{
		.name = "emutramp_available",
		.type = SARA_SECFS_READONLY_INT,
		.data = (int *) &wxprot_emutramp,
	},
	{
		.name = ".load",
		.type = SARA_SECFS_CONFIG_LOAD,
		.data = &fptrs,
	},
	{
		.name = ".dump",
		.type = SARA_SECFS_CONFIG_DUMP,
		.data = &fptrs,
	},
	{
		.name = "hash",
		.type = SARA_SECFS_CONFIG_HASH,
		.data = &fptrs,
	},
};


int __init sara_wxprot_init(void)
{
	int ret;
	struct wxprot_config_container *tmpc = NULL;

	ret = -EINVAL;
	if (!are_flags_valid(default_flags))
		goto out_fail;
	ret = -ENOMEM;
	tmpc = kzalloc(sizeof(*tmpc), GFP_KERNEL);
	if (unlikely(tmpc == NULL))
		goto out_fail;
	tmpc->buf_len = sizeof(struct binary_config_header);
	kref_init(&tmpc->refcount);
	wxprot_config = (struct wxprot_config_container __rcu *) tmpc;
	ret = sara_secfs_subtree_register("wxprot",
					  wxprot_fs,
					  ARRAY_SIZE(wxprot_fs));
	if (unlikely(ret))
		goto out_fail;
	security_add_hooks(wxprot_hooks, ARRAY_SIZE(wxprot_hooks), "sara");
	return 0;

out_fail:
	kfree(tmpc);
	return ret;
}

#endif /* CONFIG_SECURITY_SARA_WXPROT */
