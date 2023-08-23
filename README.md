# Xattr-ACL
The Xattr-ACL extended-attribute-based Linux Security Module for Linux 6.1. Tested on Fedora 38 and Debian 12 with proper functionalities.

# Before Usage
Modify accordingly and execute ```setxattr.sh``` to initialize your system. Make sure you have ```python3-xattr``` installed.
Should be enabled in the ```Security Options -> Xattr-ACL LSM``` kernel config and compiled against the Linux source provided by your distribution. This is the ONLY and ONLY MAJOR LSM and NOT compatible with others.

# Xattr and Permission Setup
| Value for Xattr "security.xattracl" | Process Privileges | File Privileges |
| --- | --- | --- |
| "trust" | Executable. All files readable including "block"ed ones. Privilege inheritable by child processes | Readable |
| "allow" | Executable. Non-"block"ed files readable | Readable |
| "block" / ... | Inexecutable | Unreadable except "trust"ed processes |
