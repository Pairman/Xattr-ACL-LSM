/* SPDX-License-Identifier: GPL-3.0-only */
/*
 * The Xattr-ACL Linux Security Module
 *
 * Author: Pairman Guo <pairmanxlr@gmail.com>
 *
 * Copyright (C) 2023 Pairman Guo <pairmanxlr@gmail.com>
 */

#define pr_fmt(fmt) "[%s] (%s) " fmt, KBUILD_MODNAME, __func__

#include <linux/binfmts.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/lsm_hooks.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/xattr.h>
#include "common.h"

/*
 * Hook definitions
 */

/**
 * xattracl_cred_alloc_blank - allocate security blob for creds
 *
 * @cred: pointer to the creds
 * @gfp: memory allocation flags
 *
 * Allocates blank security blob for creds.
 *
 * Returns 0 if successful, -ENOMEM if memory allocation fails.
 */
static int xattracl_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
	struct xattracl_sec_t *sec;

	if (!cred)
		return -ENOMEM;

	sec = (struct xattracl_sec_t *)kmalloc(sizeof(struct xattracl_sec_t),
					       gfp);
	if (!sec)
		return -ENOMEM;

	sec->value = -EPERM;
	cred->security = sec;

	return 0;
}

/**
 * xattracl_cred_free - free the security blob of creds
 *
 * @cred: pointer to the creds
 *
 * Frees the security blob of creds.
 */
static void xattracl_cred_free(struct cred *cred)
{
	if (!cred || !cred->security)
		return;

	kfree(cred->security);
	cred->security = NULL;
}

/**
 * xattracl_cred_prepare - preparing new creds for modification
 *
 * @new: pointer to the new creds
 * @old: pointer to the old creds
 * @gfp: memory allocation flags
 *
 * Preparing new creds for modification.
 *
 * Returns 0 if successful, -ENOMEM if memory allocation fails.
 */
static int xattracl_cred_prepare(struct cred *new, const struct cred *old,
				 gfp_t gfp)
{
	struct xattracl_sec_t *sec;

	if (!new)
		return 0;

	sec = (struct xattracl_sec_t *)kmalloc(sizeof(struct xattracl_sec_t),
					       gfp);
	if (!sec)
		return -ENOMEM;

	/* Default to -EPERM if old security blob doesn't exist. */
	if (!old || !old->security)
		sec->value = -EPERM;
	else
		sec->value = ((struct xattracl_sec_t *)(old->security))->value;
	new->security = sec;

	return 0;
}

/**
 * xattracl_bprm_creds_for_exec - set up security blob for binary programs
 *
 * @bprm: pointer to the linux_binprm
 *
 * Sets up security blob for binary programs from xattr or inheritance.
 *
 * Always returns 0.
 */
static int xattracl_bprm_creds_for_exec(struct linux_binprm *bprm)
{
	struct xattracl_sec_t *sec;
	struct dentry *dentry;

	sec = bprm->cred->security;
	dentry = bprm->file->f_path.dentry;
	/*
	 * Inherit sec->value if XATTR_VALUE_XATTRACL_TRUST,
	 * otherwise recheck xattr and reset.
	 */
	if (sec->value <= 0)
		sec->value = xattracl_common_file_check_xattr(dentry);

	return 0;
}

/**
 * xattracl_bprm_check_security - binary program execution control
 *
 * @bprm: pointer to the linux_binprm
 *
 * Controls binary program execution by checking the bprm's permission.
 *
 * Returns 0 if perimssion is granted.
 */
static int xattracl_bprm_check_security(struct linux_binprm *bprm)
{
	char comm[TASK_COMM_LEN];
	int value;
	int action;

	value = ((struct xattracl_sec_t *)(bprm->cred->security))->value;
	action = (current_uid().val && (value < 0));

	if (action) {
		get_task_comm(comm, current);
		pr_info("file:%s, proc:%s(%d), value:%d, action:%d\n",
			bprm->filename, comm, current->pid, value, action);
	}

	return action;
}

/**
 * xattracl_file_mprotect - memory protection control
 *
 * @vma: pointer to the virtual memory
 * @reqprot: requested memory protection mode
 * @prot: unused
 *
 * Controls memory protection mode changing requests.
 *
 * Returns 0 if successful.
 */
static int xattracl_file_mprotect(struct vm_area_struct *vma,
				  unsigned long reqprot, unsigned long prot)
{
	struct dentry *dentry;
	char comm[TASK_COMM_LEN];
	int action;

	/*
	 * Allow changing protection mode for empty memory
	 * or to non-exec requests.
	 */
	if (!(vma->vm_file) || !(reqprot & PROT_EXEC))
		return 0;

	dentry = vma->vm_file->f_path.dentry;
	action = xattracl_common_file_check_permission(dentry);

	if (action) {
		get_task_comm(comm, current);
		pr_info("file:%s, proc:%s(%d), action:%d\n",
			dentry->d_iname, comm, current->pid, action);
	}

	return action;
}

/**
 * xattracl_mmap_file - memory mapping control
 *
 * @file: pointer to the file
 * @reqprot: unused
 * @prot: protection mode for memory mapping
 * @flags: memory mapping flags
 *
 * Controls memory mapping from file by checking its permission.
 *
 * Returns 0 if mapping is allowed.
 */
static int xattracl_mmap_file(struct file *file, unsigned long reqprot,
			      unsigned long prot, unsigned long flags)
{
	struct xattracl_sec_t *sec;
	struct dentry *dentry;
	char comm[TASK_COMM_LEN];
	int action;

	sec = current_cred()->security;
	/* Allow mapping for empty or non-exec memory */
	if (current->in_execve || sec->value==1 || flags & MAP_ANONYMOUS ||
	    !(prot & PROT_EXEC))
		return 0;

	dentry = file->f_path.dentry;
	action = xattracl_common_file_check_permission(dentry);

	if (action) {
		get_task_comm(comm, current);
		pr_info("file:%s, proc:%s(%d), action:%d\n",
			dentry->d_iname, comm, current->pid, action);
	}

	return action;
}

/**
 * xattracl_file_permission - set xattr on file modification.
 *
 * @file: pointer to the file
 * @mask: unused
 *
 * Automatically sets xattr on file modification.
 *
 * Always returns 0.
 */
int xattracl_file_permission(struct file *file, int mask)
{
	struct dentry *dentry;
	char comm[TASK_COMM_LEN];

	/* Skip for non-create and non-write flags. */
	if (!(file->f_flags & O_CREAT || file->f_flags & O_WRONLY ||
	    file->f_flags & O_RDWR))
		return 0;

	/* Skip for non-regular files or pseudo filesystems. */
	dentry = file->f_path.dentry;
	if (!S_ISREG(d_backing_inode(dentry)->i_mode) ||
	    xattracl_common_file_check_fs(dentry))
		return 0;

	/* Set xattr value to XATTR_VALUE_XATTRACL_BLOCK. */
	if (xattracl_common_file_check_xattr(dentry) != -EPERM) {
		xattracl_common_file_set_xattr(dentry, -EPERM);
		get_task_comm(comm, current);
		pr_info("file:%s, proc:%s(%d), set:\"%s\"\n",
			dentry->d_iname, comm, current->pid,
			XATTR_VALUE_XATTRACL_BLOCK);
	}
	return 0;
}

/**
 * xattracl_file_open - file open control
 *
 * @file: pointer to the file
 *
 * Check permission on file open calls.
 *
 * Returns 0 if permission is granted.
 */
static int xattracl_file_open(struct file *file)
{
	struct xattracl_sec_t *sec;
	struct dentry *dentry;
	char comm[TASK_COMM_LEN];
	int action;

	if (!current_uid().val || current->in_execve)
		return 0;

	dentry = file->f_path.dentry;
	/* Skip for non-regular files or create or write-only flags. */
	if (!S_ISREG(d_backing_inode(dentry)->i_mode) ||
	    file->f_flags & O_CREAT || file->f_flags & O_WRONLY)
		return 0;

	/*
	 * Skip if process has XATTR_VALUE_XATTRACL_TRUST permission
	 * or file in a pseudo filesystem.
	 */
	sec = current_cred()->security;
	if (sec->value == 1 || xattracl_common_file_check_fs(dentry))
		return 0;

	action = xattracl_common_file_check_permission(dentry);

	if (action) {
		get_task_comm(comm, current);
		pr_info("file:%s, proc:%s(%d), action:%d\n",
			dentry->d_iname, comm, current->pid, action);
	}

	return action;
}

/**
 * xattracl_inode_rename - automatically set xattr on file rename
 *
 * @old_dir: pointer to inode of the old idrectory
 * @old_dentry: pointer to dentry of the old file
 * @new_dir: pointer to inode of the new idrectory
 * @new_dentry: pointer to dentry of the new file
 *
 * Automatically sets xattr if file moves to another directory.
 *
 * Always returns 0.
 */
static int xattracl_inode_rename(struct inode *old_dir,
				 struct dentry *old_dentry,
				 struct inode *new_dir,
				 struct dentry *new_dentry)
{
	char comm[TASK_COMM_LEN];

	/* Skip if file is to be in pseudo filesystems. */
	if (xattracl_common_file_check_fs(new_dentry))
		return 0;

	/* Skip if directory inchanged. */
	if (old_dir == new_dir)
		return 0;

	xattracl_common_file_set_xattr(old_dentry, -EPERM);

	get_task_comm(comm, current);
	pr_info("oldfile:%s, newfile:%s, proc:%s(%d), set:\"%s\"\n",
		old_dentry->d_iname, new_dentry->d_iname, comm,
		current->pid, XATTR_VALUE_XATTRACL_BLOCK);

	return 0;
}

/**
 * xattracl_inode_setxattr - setxattr control
 *
 * @mnt_userns: unused
 * @dentry: pointer to dentry of the file
 * @name: pointer to the xattr name
 * @value: pointer to the xattr value
 * @flags: unused
 *
 * Automatically sets xattr if file moves to another directory
 * or doesn't pass permission check.
 *
 * Returns 0 if setxattr is allowed.
 */
static int xattracl_inode_setxattr(struct user_namespace *mnt_userns,
				   struct dentry *dentry, const char *name,
				   const void *value, size_t size, int flags)
{
	if (strncmp(name, XATTR_SECURITY_PREFIX, XATTR_SECURITY_PREFIX_LEN))
		return 0;

	/* Only allows setxattr for XATTR_NAME_XATTRACL. */
	if (!current_uid().val &&
	    !strncmp(name, XATTR_NAME_XATTRACL, XATTR_NAME_XATTRACL_LEN))
		return 0;

	return -EPERM;
}

static struct security_hook_list xattracl_hooks[] __lsm_ro_after_init = {
	/* Binary program creds handling */
	LSM_HOOK_INIT(cred_alloc_blank, xattracl_cred_alloc_blank),
	LSM_HOOK_INIT(cred_free, xattracl_cred_free),
	LSM_HOOK_INIT(cred_prepare, xattracl_cred_prepare),
	LSM_HOOK_INIT(bprm_creds_for_exec, xattracl_bprm_creds_for_exec),

	/* Binary program execution control */
	LSM_HOOK_INIT(bprm_check_security, xattracl_bprm_check_security),

	/* Memory mapping control */
	LSM_HOOK_INIT(file_mprotect, xattracl_file_mprotect),
	LSM_HOOK_INIT(mmap_file, xattracl_mmap_file),

	/* File and inode operations control */
	LSM_HOOK_INIT(file_permission, xattracl_file_permission),
	LSM_HOOK_INIT(file_open, xattracl_file_open),
	LSM_HOOK_INIT(inode_rename, xattracl_inode_rename),
	LSM_HOOK_INIT(inode_setxattr, xattracl_inode_setxattr),
};

/**
 * xattracl_init - initialize lsm
 *
 * Initialize the Xattr-ACL Linux Security Module.
 *
 * Returns 0.
 */
static __init int xattracl_init(void)
{
	security_add_hooks(xattracl_hooks, ARRAY_SIZE(xattracl_hooks),
			   KBUILD_MODNAME);
	pr_info("module initialized\n");

	return 0;
}

DEFINE_LSM(xattracl) = {
	.name = KBUILD_MODNAME,
	.init = xattracl_init,
};
