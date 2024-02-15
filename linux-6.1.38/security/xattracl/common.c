/* SPDX-License-Identifier: GPL-3.0-only */
/*
 * Common functions for Xattr-ACL LSM
 *
 * Author: Pairman Guo <pairmanxlr@gmail.com>
 *
 * Copyright (C) 2023 Pairman Guo <pairmanxlr@gmail.com>
 */

#include <linux/cred.h>
#include <linux/magic.h>
#include <linux/xattr.h>
#include "common.h"

/*
 * Function definitions
 */

/**
 * xattracl_common_file_set_xattr - set file xattr
 *
 * @dentry: pointer to dentry of the file
 * @value: corresponding int value
 *
 * Sets the file's xattr value according to the given int value.
 */
inline void xattracl_common_file_set_xattr(struct dentry *dentry, int value)
{
	switch (value) {
	case 0:
		__vfs_setxattr(current_real_cred()->user_ns, dentry,
			       d_backing_inode(dentry), XATTR_NAME_XATTRACL,
			       XATTR_VALUE_XATTRACL_ALLOW,
			       XATTR_VALUE_XATTRACL_LEN, 0);
		break;
	case 1:
		__vfs_setxattr(current_real_cred()->user_ns, dentry,
			       d_backing_inode(dentry), XATTR_NAME_XATTRACL,
			       XATTR_VALUE_XATTRACL_TRUST,
			       XATTR_VALUE_XATTRACL_LEN, 0);
		break;
	default:
		__vfs_setxattr(current_real_cred()->user_ns, dentry,
			       d_backing_inode(dentry), XATTR_NAME_XATTRACL,
			       XATTR_VALUE_XATTRACL_BLOCK,
			       XATTR_VALUE_XATTRACL_LEN, 0);
		break;
	}
}

/**
 * xattracl_common_file_check_xattr - check file xattr
 *
 * @dentry: pointer to dentry of the file
 *
 * Checks the file's xattr.
 *
 * Returns the xattr's corresponding int value,
 * or -ENODATA if xattr value doesn't match,
 * or -ENOMEM if memory allocation fails.
 */
int xattracl_common_file_check_xattr(struct dentry *dentry)
{
	char *buf;
	int action;

	buf = (char *)kmalloc(XATTR_VALUE_XATTRACL_LEN, GFP_KERNEL);
	if (unlikely(!buf))
		return -ENOMEM;

	__vfs_getxattr(dentry, d_backing_inode(dentry), XATTR_NAME_XATTRACL,
		       buf, XATTR_VALUE_XATTRACL_LEN);
	if (!strncmp(buf, XATTR_VALUE_XATTRACL_TRUST,
	    XATTR_VALUE_XATTRACL_LEN))
		action = 1;
	else if (!strncmp(buf, XATTR_VALUE_XATTRACL_ALLOW,
		 XATTR_VALUE_XATTRACL_LEN))
		action = 0;
	else if (!strncmp(buf, XATTR_VALUE_XATTRACL_BLOCK,
		 XATTR_VALUE_XATTRACL_LEN))
		action = -EPERM;
	else
		action = -ENODATA;

	kfree(buf);

	return action;
}

/**
 * xattracl_common_file_check_permission - check file permission
 *
 * @dentry: pointer to dentry of the file
 *
 * Checks permission by checking uid and file xattr.
 *
 * Returns 0 if permission is granted.
 */
inline int xattracl_common_file_check_permission(struct dentry *dentry)
{
	/* Always grant permission for root user. */
	return (current_uid().val &&
		xattracl_common_file_check_xattr(dentry) < 0) ? -EPERM : 0;
}



/**
 * xattracl_common_file_check_fs - check filesystem type
 *
 * @dentry: pointer to dentry of the file
 *
 * Checks if the file is in a pseudo filesystem.
 *
 * Returns -EOPNOTSUPP if the file is in a pseudo filesystem.
 */
inline int xattracl_common_file_check_fs(struct dentry *dentry)
{
	switch (dentry->d_sb->s_magic) {
	case PROC_SUPER_MAGIC:
	case SYSFS_MAGIC:
	case DEVPTS_SUPER_MAGIC:
	case CGROUP_SUPER_MAGIC:
	case CGROUP2_SUPER_MAGIC:
	case PIPEFS_MAGIC:
	case SOCKFS_MAGIC:
		return -EOPNOTSUPP;
	default:
		return 0;
	}
}
