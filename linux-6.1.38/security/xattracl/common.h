/* SPDX-License-Identifier: GPL-3.0-only */
/*
 * Header file for Xattr-ACL LSM
 *
 * Author: Pairman Guo <pairmanxlr@gmail.com>
 *
 * Copyright (C) 2023 Pairman Guo <pairmanxlr@gmail.com>
 */

#ifndef _SECURITY_XATTRACL_COMMON_H
#define _SECURITY_XATTRACL_COMMON_H


/*
 * Name of Xattr-ACL LSM.
 */

/*
 * Xattr name, values and their sizes
 * as we introduce the three-level access control.
 * XATTR_VALUE_XATTRACL_TRUST: allow execution or reading both itself
 *			       or inherited
 * XATTR_VALUE_XATTRACL_ALLOW: allow execution or reading itself
 * XATTR_VALUE_XATTRACL_BLOCK: block execution or reading
 */
#define XATTR_XATTRACL_SUFFIX		"xattracl"
#define XATTR_NAME_XATTRACL	XATTR_SECURITY_PREFIX XATTR_XATTRACL_SUFFIX
#define XATTR_NAME_XATTRACL_LEN		13
#define XATTR_VALUE_XATTRACL_TRUST	"trust"
#define XATTR_VALUE_XATTRACL_ALLOW	"allow"
#define XATTR_VALUE_XATTRACL_BLOCK	"block"
#define XATTR_VALUE_XATTRACL_LEN	5

/*
 * Security blob for storing int value corresponding to xattr value.
 * 1: XATTR_VALUE_XATTRACL_TRUST
 * 0: XATTR_VALUE_XATTRACL_ALLOW
 * -EPERM: XATTR_VALUE_XATTRACL_BLOCK and others
 */
struct xattracl_sec_t {
	int value;
};

/*
 * Function prototypes
 */
inline void xattracl_common_file_set_xattr(struct dentry *dentry, int action);
int xattracl_common_file_check_xattr(struct dentry *dentry);
inline int xattracl_common_file_check_permission(struct dentry *dentry);
inline int xattracl_common_file_check_fs(struct dentry *dentry);

#endif /* _SECURITY_XATTRACL_COMMON_H */
