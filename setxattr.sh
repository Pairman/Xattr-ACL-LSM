#!/bin/bash

username="pairman"
fmt="[setxattr.sh]"
setxattr_dirs=("/usr/"{"bin","games","include","lib","lib32","lib64","libexec","libx32","local","sbin","share","src"} "/etc" "/boot" "/var" "/opt/"{"VBoxGuestAdditions-7.0.10","setxattr.sh"} {"/root/","/home/$username/"}{".bash_history",".bash_logout",".bashrc",".profile",".ssh",".viminfo",".vimrc"});

setxattr_func(){
	echo "$fmt $1: Started.";
	sudo find $1 -type f -exec xattr -w security.xattracl allow '{}' \;
	echo "$fmt $1: Done.";
}

echo "$fmt Initialize xattrs for Xattr-ACL LSM."
echo "$fmt You should change \$username to your username."

for dir in ${setxattr_dirs[@]}
do
	setxattr_func $dir &
done

wait
echo "$fmt All done."
