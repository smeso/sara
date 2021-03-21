// SPDX-License-Identifier: GPL-2.0

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

#include "include/dfa.h"
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

struct wxprot_config_container {
	struct sara_dfa_tables *dfa;
	struct kref refcount;
};

static struct wxprot_config_container __rcu *wxprot_config;

static const int wxprot_config_version = SARA_WXPROT_CONFIG_VERSION;
static int wxprot_enabled __read_mostly = true;
static DEFINE_SPINLOCK(wxprot_config_lock);

static u16 default_flags __lsm_ro_after_init =
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

module_param(wxprot_enabled, int, 0);
MODULE_PARM_DESC(wxprot_enabled,
		 "Disable or enable SARA WX Protection at boot time.");

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
		 "Disable or enable SARA WX Protection at boot time.");

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


/*
 * This is a big define, but I didn't find any better way to avoid
 * duplicating code when handling elf{32,64}_hdr and elf{32,64}_phdr.
 */
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
static int sara_bprm_creds_for_exec(struct linux_binprm *bprm)
{
	int i;
	struct wxprot_config_container *c;
	u16 sara_wxp_flags = default_flags;
	sara_dfa_output outfl;
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
		if (sara_dfa_match(c->dfa, path, &outfl))
			sara_wxp_flags = (u16) outfl;
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

#define sara_violation(msg) ({				\
	if ((sara_wxp_flags & SARA_WXP_VERBOSE))	\
		pr_wxp(msg);				\
	!(sara_wxp_flags & SARA_WXP_COMPLAIN);		\
})

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
		     vm_flags & VM_EXEC &&
		     sara_violation("W^X")))
		return -EPERM;
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
		     get_current_sara_mmap_blocked() &&
		     sara_violation("executable mmap")))
		return -EPERM;

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
			if (sara_wxp_flags & SARA_WXP_OTHER &&
			    sara_violation("mprotect on file mmap"))
				return -EACCES;
		} else if (vma->vm_start >= vma->vm_mm->start_brk &&
			vma->vm_end <= vma->vm_mm->brk) {
			if (sara_wxp_flags & SARA_WXP_HEAP &&
			    sara_violation("mprotect on heap"))
				return -EACCES;
		} else if ((vma->vm_start <= vma->vm_mm->start_stack &&
			    vma->vm_end >= vma->vm_mm->start_stack) ||
			   vma_is_stack_for_current(vma)) {
			if (sara_wxp_flags & SARA_WXP_STACK &&
			    sara_violation("mprotect on stack"))
				return -EACCES;
		} else if (sara_wxp_flags & SARA_WXP_OTHER &&
			   sara_violation("mprotect on anon mmap"))
			return -EACCES;
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
		      !(vma->vm_flags & VM_WRITE)))) {
		if (sara_violation("W^X"))
			return -EACCES;
	}

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

static struct security_hook_list wxprot_hooks[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(bprm_creds_for_exec, sara_bprm_creds_for_exec),
	LSM_HOOK_INIT(check_vmflags, sara_check_vmflags),
	LSM_HOOK_INIT(shm_shmat, sara_shm_shmat),
	LSM_HOOK_INIT(file_mprotect, sara_file_mprotect),
};

static void config_free(struct wxprot_config_container *data)
{
	sara_dfa_free_tables(data->dfa);
	kfree(data);
}

static bool are_flags_valid_dfa(sara_dfa_output flags)
{
	return are_flags_valid((u16) flags);
}

static int config_load(const char *buf, size_t buf_len)
{
	struct sara_dfa_tables *dfa = NULL;
	struct wxprot_config_container *new;
	int ret;

	dfa = sara_dfa_load(buf, buf_len, are_flags_valid_dfa);
	if (IS_ERR_OR_NULL(dfa)) {
		if (IS_ERR(dfa))
			ret = PTR_ERR(dfa);
		else
			ret = -EINVAL;
		goto error;
	}
	new = kmalloc(sizeof(*new), GFP_KERNEL);
	if (unlikely(!new)) {
		ret = -ENOMEM;
		goto error_dfa;
	}
	kref_init(&new->refcount);
	new->dfa = dfa;
	SARA_CONFIG_REPLACE(wxprot_config,
			    new,
			    config_free,
			    &wxprot_config_lock);
	pr_notice("WXP: new rules loaded.\n");
	return 0;
error_dfa:
	sara_dfa_free_tables(dfa);
error:
	pr_notice("WXP: failed to load rules.\n");
	return ret;
}

static ssize_t config_dump(char **buf)
{
	ssize_t ret;
	struct wxprot_config_container *c;

	SARA_CONFIG_GET(c, wxprot_config);
	ret = sara_dfa_dump(c->dfa, buf);
	SARA_CONFIG_PUT(c, config_free);
	return ret;
}

static int config_hash(char **buf)
{
	int ret;
	struct wxprot_config_container *config;

	ret = -ENOMEM;
	*buf = kzalloc(sizeof(config->dfa->hash), GFP_KERNEL);
	if (unlikely(*buf == NULL))
		goto out;

	SARA_CONFIG_GET_RCU(config, wxprot_config);
	memcpy(*buf, config->dfa->hash, sizeof(config->dfa->hash));
	SARA_CONFIG_PUT_RCU(config);

	ret = 0;
out:
	return ret;
}

static DEFINE_SARA_SECFS_BOOL_FLAG(wxprot_enabled_data,
				   wxprot_enabled);

static struct sara_secfs_fptrs fptrs __lsm_ro_after_init = {
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
	kref_init(&tmpc->refcount);
	tmpc->dfa = sara_dfa_make_null();
	if (unlikely(!tmpc->dfa))
		goto out_fail;
	wxprot_config = (struct wxprot_config_container __rcu *) tmpc;
	ret = sara_secfs_subtree_register("wxprot",
					  wxprot_fs,
					  ARRAY_SIZE(wxprot_fs));
	if (unlikely(ret))
		goto out_fail_dfa;
	security_add_hooks(wxprot_hooks, ARRAY_SIZE(wxprot_hooks), "sara");
	return 0;

out_fail_dfa:
	sara_dfa_free_tables(tmpc->dfa);
out_fail:
	kfree(tmpc);
	return ret;
}

#endif /* CONFIG_SECURITY_SARA_WXPROT */
