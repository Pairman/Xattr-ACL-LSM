# Xattr-ACL-LSM
The Xattr-ACL extended-attribute-based Linux Security Module for Linux 6.1. Tested on Fedora 38 and Debian 12 with proper functionalities.

# Before Usage
Modify accordingly and execute ```setxattr.sh``` to initialize your system. Make sure you have ```python3-xattr``` installed.
Should be enabled in the ```Security Options -> Xattr-ACL LSM``` kernel config and compiled against the Linux source provided by your distribution. This is the ONLY and ONLY MAJOR LSM and NOT compatible with others.

# Xattr and Permission Setup
| Value for Xattr Name "security.perm" | Process Privileges | File Privileges |
| --- | --- | --- |
| "trust" | Executable. Open all files including "block"ed ones. Privilege will be inherited by all child processes. | Readable |
| "allow" | Executable. Open non-"block"ed files | Readable |
| "block" / ... | Inexecutable | Unreadable except "trust"ed processes |
