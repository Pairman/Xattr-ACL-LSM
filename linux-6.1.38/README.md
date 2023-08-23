# linux-6.1.38
## 内容：
### 1. 
包含Xattr-ACL安全模块（在内核中标识符为xattracl）及各级Kconfig、Makefile。

### 2. 
包含.config文件，版本字符串设为“6.1.38-xattracl”，已启用Xattr-ACL模块、精简了部分驱动（基本上仅保留了桥接网卡和虚拟显卡驱动），经验证在VirtualBox x86_64/Debian 12（最小安装） x86_64环境上可正常运行（需使用官方源提供的linux-source 6.1.38-1编译）。

## 实现
（源码文件内均有相应注释）
1. common.c \
&emsp;&emsp;```xattracl_common_file_set_xattr```：通用xattr设置函数； \
&emsp;&emsp;```xattracl_common_file_check_xattr```：通用xattr检查函数； \
&emsp;&emsp;```xattracl_common_file_check_permission```：通用权限检查函数； \
&emsp;&emsp;```xattracl_common_file_set_xattr```：通用文件系统检查函数。

2. xattracl.c \
&emsp;&emsp;```xattracl_cred_alloc_blank```, ```xattracl_cred_free```, ```xattracl_cred_prepare```, ```xattracl_bprm_creds_for_exec```：程序执行权限载入和卸载函数； \
&emsp;&emsp;```xattracl_bprm_check_security```：程序执行管控； \
&emsp;&emsp;```xattracl_mmap_file```, ```xattracl_file_mprotect```：动态库加载管控； \
&emsp;&emsp;```xattracl_file_permission```：文件新建/修改自动设置xattr； \
&emsp;&emsp;```xattr_file_open```：文件读取管控； \
&emsp;&emsp;```xattracl_inode_rename```, ```xattracl_inode_setxattr```：文件移动/重命名/设置xattr控制。

## 用法:
### 1. 配置
采用此处提供的.config，或者自己```make menuconfig```启用和添加安全模块xattracl。

### 2. 编译
编译内核及模块：```make -jN```，N为自己的CPU核心数。

### 3. 安装
安装内核及模块：```sudo make -jN modules_install```、```sudo make -jN install```。

### 4. 重启
重启并自行测试相关功能。

## 目前已实现的功能及实例
### 应用程序直接执行管控

（注：为了直观，以下示例均仅包含关键的dmesg信息，需要者可自行编译运行该模块以验证。）

1. 只允许执行授权的程序

```
[pairman@debian log]$ xattr -slz 1.sh
security.perm: block
[pairman@debian log]$ ./1.sh
[   59.327953] [xattracl] (xattracl_bprm_check_security) file:1.sh, proc:bash(562), value:-1, action:-1
[   59.329791] [xattracl] (xattracl_file_open) file:1.sh, proc:bash(562), action:-1
bash: ./1.sh: Operation not permitted
[pairman@debian log]$ sudo xattr -w security.perm allow 1.sh
[pairman@debian log]$ ./1.sh
Hello World
```

2. 只允许加载授权的动态库文件

```
[pairman@debian lib]$ sudo cat hello.c
#include <stdio.h>
#include "hello.h"

void hello()
{
	puts("Hello World\n");
}
[pairman@debian lib]$ sudo cat hello.h
#ifndef _HELLO_WORLD_H
#define _HELLO_WORLD_H

void hello();

#endif
[pairman@debian lib]$ sudo cat main.c
#include "hello.h"

int main()
{
	hello();
	return 0;
}
[pairman@debian lib]$ gcc -fPIC -shared -o libhello.so hello.c
[pairman@debian lib]$ gcc -o main main.c -L./ -lhello
[pairman@debian lib]$ export LD_LIBRARY_PATH=.
[pairman@debian lib]$ sudo xattr -w security.perm allow main
[pairman@debian lib]$ ./main
[  153.427569] [xattracl] (xattracl_file_open) file:libhello.so, proc:main(583), action:-1
bash: ./1.sh: Operation not permitted
./main: error while loading shared libraries: libhello.so: cannot open shared onject file: No such file or directory
[pairman@debian lib]$ sudo xattr -w security.perm allow libhello.so
[pairman@debian lib]$ ./main
Hello World
```

   

3. 文件新增、修改或移动后自动具备未授权标识

```
[pairman@debian log]$ xattr -slz 1
security.perm: allow
[pairman@debian log]$ mv 1 2
[pairman@debian log]$ xattr -slz 2
security.perm: allow
[pairman@debian log]$ mv 2 dir/3
[  225.528489] [xattracl] (xattracl_inode_rename) oldfile:2, newfile:3, proc:mv(605), set:"block"
[pairman@debian log]$ xattr -slz dir/3
security.perm: block
```

```
[pairman@debian log]$ wget --quiet www.baidu.com
[  260.730872] [xattracl] (xattracl_file_permission) file:index.html, proc:wget(608), set:"block"
[pairman@debian log]$ xattr -slz index.html
security.perm: block
```

```
[pairman@debian log]$ echo '' > 4
[  225.577695] [xattracl] (xattracl_file_permission) file:4, proc:bash(551), set:"block"
[pairman@debian log]$ xattr -slz 4
security.perm: block
```

### 扩展标记具备继承能力

2. 允许对已授权应用执行临时释放的应用程序和文件

```
[pairman@debian log]$ sudo cat 4.c
#include <stdio.h>
#include <stdlib.h>

int main()
{
	puts("---begin 4---\n");
	system("./tmp.sh");
	puts("----end 4----\n");
	return 0;
}
[pairman@debian log]$ gcc -o 4 4.c
[pairman@debian log]$ xattr -w security.perm allow 4 tmp.sh
[pairman@debian log]$ ./4
---begin 4---
[   59.327953] [xattracl] (xattracl_bprm_check_security) file:tmp.sh, proc:bash(570), value:-1, action:-1
bash: ./1.sh: Operation not permitted
sh: 1: ./tmp.sh: Operation not permitted
----end 4----
[pairman@debian log]$ xattr -w security.perm trust 4
[pairman@debian log]$ ./4
---begin 4---
Hello World
----end 4----
```

### 脚本文件执行控制

1. 通过解释器的脚本执行管控

```
[pairman@debian log]$ xattr -slz 1.sh
security.perm: block
[pairman@debian log]$ sh 1.sh
[  299.229425] [xattracl] (xattracl_file_open) file:1.sh, proc:sh(614), action:-1
sh: 0: cannot open 1.sh: Operation not permitted
[pairman@debian log]$ sudo xattr -w security.perm allow 1.sh
[pairman@debian log]$ sh 1.sh
Hello World
```
```
[pairman@debian tmp]$ xattr -slz 1.py
security.perm: block
[pairman@debian log]$ python3 1.py
[   36.905125] [xattracl] (xattracl_file_open) file:1.py, proc:python3(559), action:-1
[   36.905192] [xattracl] (xattracl_file_open) file:1.py, proc:python3(559), action:-1
python3: can't open file '/tmp/1.py': [Errno 1] Operation not permitted
[pairman@debian tmp]$ sudo xattr -w security.perm allow 1.py
[pairman@debian tmp]$ python3 1.py
Hello World
```

2. 通过管道的脚本执行管控

```
[pairman@debian log]$ xattr -slz 1.sh
security.perm: block
[pairman@debian log]$ cat 1.sh | sh
[  303.227737] [xattracl] (xattracl_file_open) file:1.sh, proc:cat(619), action:-1
cat: 1.sh: Operation not permitted
[pairman@debian log]$ sudo xattr -w security.perm allow 1.sh
[pairman@debian log]$ cat 1.sh | sh
Hello World
```
```
[pairman@debian tmp]$ xattr -slz 1.py
security.perm: block
[pairman@debian log]$ cat 1.py | python3
[   40.530024] [xattracl] (xattracl_file_open) file:1.py, proc:cat(561), action:-1
cat: 1.py: Operation not permitted
[pairman@debian tmp]$ sudo xattr -w security.perm allow 1.py
[pairman@debian tmp]$ cat 1.py | python3
Hello World
```

3. 通过重定向的脚本执行管控

```
[pairman@debian log]$ xattr -slz 1.sh
security.perm: block
[pairman@debian log]$ sh < 1.sh
[  314.228009] [xattracl] (xattracl_file_open) file:1.sh, proc:bash(620), action:-1
bash: 1.sh: Operation not permitted
[pairman@debian log]$ sudo xattr -w security.perm allow 1.sh
[pairman@debian log]$ sh < 1.sh
Hello World
```
```
[pairman@debian tmp]$ xattr -slz 1.pysecurity.perm: block
[pairman@debian log]$ python3 < 1.py
[   47.120900] [xattracl] (xattracl_file_open) file:1.py, proc:bash(560), action:-1
bash: 1.py: Operation not permitted
[pairman@debian tmp]$ sudo xattr -w security.perm allow 1.py
[pairman@debian tmp]$ python3 < 1.py
Hello World
```
