# 相关信息

kali：1.0.0.3/24

靶机：1.0.0.4/24

靶机介绍：[Vikings: 1 ~ VulnHub](https://www.vulnhub.com/entry/vikings-1,741/)

靶机下载：https://download.vulnhub.com/vikings/Vikings.ova

难度：低（中）

# 文字思路

## 全流程思路：

主机发现	端口扫描	

WEB信息搜集：在里面我们发现了个 `base64`的编码文本

编码转换/文件还原：为加密的 `zip`文件

离线密码破解	隐写技术	

二进制文件提取：为一个压缩包 `zip`,给予登陆密码提示

素数查找/克拉茨猜想：登陆密码提示

RPC漏洞提权



## 局部思路

### 数据流的分析

1. 确认编码：是否加密，是否压缩（通过计算熵值来判断）
2. 确认数据流的格式（文件头或者使用相关工具）
3. 进行相关的查看和解密

### 文件的隐写

1. 直接上工具查看

2. 查看二进制

    

## 下意识的操作

1. 当数据流以字母 "PK" 开头时，很可能是 ZIP 文件格式。ZIP 文件的文件头部分包含标识符 "PK"，这是 ZIP 文件格式的标志之一。
2. 查看 `/etc/passwd`文件，寻找 `/bin/`

## 主要的知识点

1. RPC漏洞

# 具体流程

## 信息搜集

1. 主机发现，端口扫描，版本确认。我们直接 `nmap`出了一个 `web`目录 `/site`

    <img src="https://image.cchl.fun/kali_image/image-20230526142616097.png" alt="image-20230526142616097" style="zoom:50%;" />

2. 访问靶机的 `ip`和发现的相关文本路径。然后查看网页的源码，查找相关的路径，api，注释等。依然没有什么收获。

    <img src="https://image.cchl.fun/kali_image/image-20230526142838020.png" alt="image-20230526142838020" style="zoom:50%;" />

    这个网页的其他链接也是假链接，都是指向本页面的。

    <img src="https://image.cchl.fun/kali_image/image-20230526142923643.png" alt="image-20230526142923643" style="zoom:50%;" />

3. 接下来就是常规的操作，目录爬取（迭代的进行爬取）当迭代的爬取 `/site`的时候我们发现了一个 `war.txt`的文件。至于其他的没有什么价值。

    <img src="https://image.cchl.fun/kali_image/image-20230526145936987.png" alt="image-20230526145936987" style="zoom:67%;" />

    然后访问该文件，通过回显的内容`/war-is-over`。我们很自然的判断这也是 `web`路径。我们进一步访问发现回显了大量的数据。

    <img src="https://image.cchl.fun/kali_image/image-20230526150223883.png" alt="image-20230526150223883" style="zoom:67%;" />

    <img src="https://image.cchl.fun/kali_image/image-20230526150535281.png" alt="image-20230526150535281" style="zoom: 33%;" />

4. 通过访问 `/war-is-over`，我们可以很简单判断出这是个 `base64`编码的文件，具有明显的 `base64`特征。所以我采用 

    https://cyberchef.org 这个网站的 `From Base64`模块来进行解码。但是我们发现解码出来的数据我们依然看不懂。                         [==Cyberchef的介绍==](#back2)<a id='tag2'></a>

    <img src="https://image.cchl.fun/kali_image/image-20230526151531859.png" alt="image-20230526151531859" style="zoom: 50%;" />

    不过我们通过数据流的 `PK`这个打头的信息，我们应该敏感的察觉这很有可能为一个 `zip`压缩包。我们通过 `Entropy`模块也可以判断出这个解密出来的数据流很可能经过人为的加密或混淆。因为计算出的 `熵值` 大于 `7.5`

    <img src="https://image.cchl.fun/kali_image/image-20230526152215490.png" alt="image-20230526152215490" style="zoom: 80%;" />

    进一步的通过 `Detect File Type`模块判断文件类型果然为 `zip`。但是当我们将其保存为 `a.zip` 打开的时候发现是需要密码的。

    <img src="https://image.cchl.fun/kali_image/image-20230526153021946.png" alt="image-20230526153021946" style="zoom:67%;" />

    <img src="https://image.cchl.fun/kali_image/image-20230526153225741.png" alt="image-20230526153225741" style="zoom: 50%;" />

## zip密码破解

1. `zip2john`工具先将 `a.zip`的密码==提出==来转化为 `john`可以处理的格式。然后是使用 `john`进行密码破解，发现密码为：`ragnarok123`

    <img src="https://image.cchl.fun/kali_image/image-20230526155657644.png" alt="image-20230526155657644" style="zoom:67%;" />

2. 打开后发现为一张图片，结合 `CTF`自然而然的想到是存在数据的隐写可能的。

    <img src="https://image.cchl.fun/kali_image/1282531-20211211142817679-959299550.png" alt="image-20230526155657644" style="zoom:67%;" />

## 隐写的破解

1.    我们使用 `steghide`工具来帮助我们判断。但是当我们发现的时候它提示我们是需要密码的，这反而更加的让我们确信图片里面存在隐写的数据

    <img src="https://image.cchl.fun/kali_image/image-20230526160825442.png" alt="image-20230526160825442" style="zoom: 50%;" />

2. 进行密码的破解：

    1. 方法一：自己写个 `bash`脚本，但是效率太低，无法实现多线程。而且由于字典太大破解速度非常缓慢，而且密码爆破不出来。

        `steghide extract king -p $i` [==命令解释===](#back3)<a id='tag3'></a>

        ```bash
        for i in $(cat "rockyou.txt");do steghide extract king -p $i;done
        ```

    2. 方法二：我们是否可以直接对 `king`图片进行二进制的数据分析，暂时的忽略密码验证。看能不能直接从二进制中提取出隐写的数据。我们使用 `binwalk`工具进行查看，每个行的大致解释：

        - 0：为jpeg格式的图片
        - 12：为图片的具体内容
        - 1429567：为一个 `zip`压缩文件，压缩的大小为：53，解压后为：92。里面的文件名为  `user`
        - 1429740：`zip`压缩文件的结束位置

        <img src="https://image.cchl.fun/kali_image/image-20230526162646855.png" alt="image-20230526162646855" style="zoom:50%;" />

    3. 进行隐写文件的提取，然后进行查看发现为一段文本我们发现该文本具有非常明显的 `ssh`的特征。

        <img src="https://image.cchl.fun/kali_image/image-20230526162844325.png" alt="image-20230526162844325" style="zoom:50%;" />

        <img src="https://image.cchl.fun/kali_image/image-20230526163956387.png" alt="image-20230526163956387" style="zoom:50%;" />

## 突破边界

1. 我们进行 `ssh`登陆的不断尝试，直到 `user:floki passwd:f@m0usboatbuilde7` 我们才成功的登陆。

    <img src="https://image.cchl.fun/kali_image/image-20230526164529489.png" alt="image-20230526164529489" style="zoom:50%;" />

2. 进行一系列的数据收集，而且无法直接 `sudo -s` 。我们发现了一个非常有趣的用户 `ragnar`也是能使用 `shell`

    <img src="https://image.cchl.fun/kali_image/image-20230526164856633.png" alt="image-20230526164856633" style="zoom:67%;" />

3. 我们发现在用户目录下有个非常明显的提示文件 `readme.txt, boat`,当我阅读文件内容全部的时候可以发现它提示我们两个非常有用的信息：1，`ragnar`           2，`create this boat`

    然后我们阅读 `boat`这个为一个伪代码。意思：可打印的字符是你的帮手，`num`=第 `29`个素数，将 `num`放入到 `collatz-conjecture(num)`函数中，我们可以猜测当经过函数处理后会生成一系列数据，然后将可打印的提取出来。估计就是 `ragnar`的密码。

    ![image-20230526174641840](https://image.cchl.fun/kali_image/image-20230526174641840.png)

4. 第 `29`个素数的python代码，结果为 `109`

    <img src="https://image.cchl.fun/kali_image/image-20230526193435141.png" alt="image-20230526193435141" style="zoom: 50%;" />

    ```python
    def find(n):
        if n in [1]:
            if n == 1:
                print(f"第{n}个素数: 2")
            return
        number = 3
        count = 1
        while True:
            i = 0
            mid = int(number/2) + 1
            for i in range(2, mid + 1):
                if number % i == 0:
                    break
            else:
                count += 1
            if count == n:
                print(f"第{n}个素数: {number}")
                return
            number += 1
    if __name__ == "__main__":
        n = 29 # 用于指定你要找的素数是第几个
        find(n)
    ```

5. `collatz-conjecture(num)`的实现：翻译过来就是 ==考拉兹猜想==，猜想的介绍。：

    [陶哲轩接近证明考拉兹猜想_新浪科技_新浪网 (sina.com.cn)](https://tech.sina.com.cn/roll/2019-12-15/doc-iihnzhfz5997311.shtml)

    这个脚本是结合 `可打印的字符是你的帮手`这个提示消息，将在考拉兹猜想过程中产生的中间值==进行筛选后==进行输出

    ==不要问为什么这个提示就是这个意思呢？==我感觉还是要你打靶经验，做题经验来帮助你推断的

    <img src="https://image.cchl.fun/kali_image/image-20230526201649977.png" alt="image-20230526201649977" style="zoom: 50%;" />

    ```python
    number = 109
    a = [number]
    while number != 1:
        if number % 2 == 1:
            number = number * 3 + 1
        else:
            number //= 2
        if number <  and number >32: # 进行是否为ascii 可打印字符的判断
            a.append(number)
    print(a)
    ```

6. 然后再使用 `CyberChef`来进行编码，我们可以大胆的尝试将其认为是 `ragnar`的密码

    `Delimiter`:分隔符                 `Comma`:逗号，顿号

    ![image-20230526201702226](https://image.cchl.fun/kali_image/image-20230526201702226.png)

7. 进行登陆，登陆成功但是系统还要我们输入一次密码（有没有可能是我们一登陆这个用户，系统就自动的跑了一些需要高权限的程序？==---->==查看自启==动的配置文件==），我们还是用 `mR)|>^/Gky[gz=\.F#j5P(`  这个密码。输入的时候发现错误，提示 `ragnar`不在 `sudoer`组内。

    <img src="https://image.cchl.fun/kali_image/image-20230526202253412.png" alt="image-20230526202253412" style="zoom:50%;" />

    但是如果我们抛开视频的思路不谈，如果就用登陆成功的 `floki`的 `shell` 进行 `su ragnar`是不会发现我们还需要输入第二次密码来运行一个程序的。那么这个提示我们要查看==自启动配置文件==的提示就很容易忽略。

    <img src="https://image.cchl.fun/kali_image/image-20230526202455474.png" alt="image-20230526202455474" style="zoom:67%;" />

    同时我们为了交互的方便将原本的 shell换为 `bash`来方便交互。

    <img src="https://image.cchl.fun/kali_image/image-20230526204056590.png" alt="image-20230526204056590" style="zoom:67%;" />

    拿下第一个 `flag`

    ![image-20230527094342916](https://image.cchl.fun/kali_image/image-20230527094342916.png)

## RPC漏洞利用

1. 我通过查看和用户 `ragnar` 登陆自启动的相关配置文件来查看到底是哪个程序需要高权限才能运行，当我们浏览到 `.profile`文件的时候我们发现了目标为一个 `python`的脚本。                                [==.profile是什么文件？==](#back8)<a id='tag8'></a>

    <img src="https://image.cchl.fun/kali_image/image-20230526204311699.png" alt="d" style="zoom: 50%;" />

2. 查看该脚本和它的相关权限，发现该脚本只有 `root`用户有读写的权限，其他的所有用户只有读和执行的权限。

    ![image-20230527083036656](https://image.cchl.fun/kali_image/image-20230527083036656.png)

    该脚本已经大致的注释了该脚本的使用方法，同时我们应该敏锐的发现 `rpyc`是python中一个用来 `RPC`的一个模块。

    ![image-20230527083226785](https://image.cchl.fun/kali_image/image-20230527083226785.png)

    同时我们发现服务端也是打开了 `rpyc`服务端的端口的，

3. 接下来的大致思路就是利用 `RPC`来让靶机替我们执行程序：

    - 让靶机的高权限用户反弹shell。       			==这些方法都要建立在，RPC漏洞是由高权限用户导致的==
    - 让靶机执行提权脚本             
    - 让靶机提升我们已经获得的用户权限。                      [==rpyc大致用法==](#tag4)<a id='back4'></a>

    我们选择3来进行尝试，通过阅读 `rpyc`模块的官方文档，我们可以大致的进行编程出一个脚本。请参考官网的教程，非常简单。就是将 `shell`函数从客户端传递给服务端。在服务端本地执行 `shell`函数。只是这里的客户端和服务端都为靶机。

    [Part 1: Introduction to Classic RPyC — RPyC](https://rpyc.readthedocs.io/en/latest/tutorial/tut1.html)

    ```python
    import rpyc
    def shell(): 		# shell函数将 ragnar加入到sudo这个组中。
        import os
        os.system("sudo usermod -a -G sudo ragnar")
    conn = rpyc.classic.connect("localhost")
    fn = conn.teleport(shell)	# fu是一个在服务端执行的函数，其实就是 shell函数
    fn()
    ```

    ![image-20230527095803335](https://image.cchl.fun/kali_image/image-20230527095803335.png)

4. 再次 `ragnar` 登陆查看是否提权成功。我们进行 `id`的查看发现我们是在 `sudo`组中的，然后直接 `sudo -s`切换为 `root`。拿下 `flag`

    ![image-20230527101121630](https://image.cchl.fun/kali_image/image-20230527101121630.png)

# 相关工具/命令

## 命令

### ss

1. what?

    于查看和分析 Linux 系统的网络连接和套接字信息。

2. 具体实例

    1. `ss -pantu`：将显示所有的 TCP 和 UDP 连接信息，并附带进程信息和禁用名称解析，以 IP 地址和端口号的形式显示。
        - `-p`：显示进程信息，即显示与网络连接相关的进程信息。
        - `-a`：显示所有套接字，包括监听和非监听状态的套接字。
        - `-n`：禁用名称解析，以 IP 地址和端口号的形式显示连接信息。
        - `-t`：显示 TCP 连接。
        - `-u`：显示 UDP 连接。
    
         这条命令同 `netstat -tuln`：你可以获得当前系统上哪些端口正在被监听以及与哪些 IP 地址建立了连接
    
        - `-t`：表示显示 TCP 连接信息。
        - `-u`：表示显示 UDP 连接信息。
        - `-l`：表示仅显示监听（Listening）状态的连接。
        - `-n`：表示以数字形式显示 IP 地址和端口号，而不进行反向解析。既 `ip`转换为 `主机名`的过程。
        - 

### usermod

1. what?

    用于修改用户账户的属性和配置

2. 具体实例

    1. usermod -a -G sudo ragnar
        - `-a` 参数用于向用户添加附加组。通过 `-a` 参数，可以将用户添加到一个或多个附加组中，而不会影响用户的主组
        - `-G, --groups eg:-G group <用户名>`：修改用户的附加组。
    2. 相关参数
        - `-l, --login NEW_LOGIN`：修改用户的登录名（用户名）。
        - `-d, --home HOME_DIR`：修改用户的主目录路径。
        - `-s, --shell SHELL`：修改用户的登录Shell。
        - `-g, --gid GROUP`：修改用户的主组（用户组）。
        - `-u, --uid UID`：修改用户的用户ID。
        - `-p, --password PASSWORD`：设置用户的密码（已加密）。
        - 

## 工具

### binwakl

1. what?

    一款用于分析二进制文件的工具，它可以扫描给定的文件，并尝试识别其中的隐藏信息和嵌入式文件

2. 具体实例

    1. binwalk -e king --run-as=root：-e是需要调用一些权限需要知道用户。
    
    2. 相关参数：
        - `e` 或 `--extract`：提取嵌入在文件中的其他文件。
        
        - `-y` 或 `--depth`：指定扫描的深度级别。
        
        - `-r` 或 `--raw`：以原始模式扫描文件，而不使用任何特征签名。
        
        - `-B` 或 `--signature`：使用指定的签名数据库文件进行扫描。
        
        - `-D` 或 `--dumb`：禁用智能扫描和递归扫描。
        
        - `-z` 或 `--carve`：对已知的文件类型进行深入的文件恢复操作。
        
        - `-l` 或 `--list`：显示可用的签名数据库。
        
        - `-x` 或 `--exclude`：排除指定类型的文件。
        
        - `-m` 或 `--matryoshka`：使用递归扫描模式。
        
            

### steghide

1. what?

    可以测定目标文件是否有隐写的数据，同时还可以进行相关一个隐写数据的提取。

2. 具体实例

    1. steghide info file：判断该文件是否有隐写的可能。
    
    2. steghide extract king -p 1234                 [==返回==](#tag3)<a id='back3'></a>
        - extract king：表示要提取隐数据，文件为 `king`
        
        - -p 1234：提取时的密码为 `1234`
        
            

### CyberChef

1. what？                                          [==返回==](#tag2)<a id='back2'></a>

    ==这是一个网站==，CyberChef 是一个网站和工具，用于执行各种数据操作和转换。它可以帮助您处理、分析和转换各种类型的数据，包括文本、编码、哈希、加密、压缩等。

2. 具体功能                                   (其实是非常简单的，自己看看就会)

    1. Entropy(熵)：用来判断一个数据的 ==混乱程度==。如果计算后的 `熵`值大于 `7.5`后基本可以确认这个数据是结果人为的 混淆和加密

    2. Detect File Type：用于确认文件是什么格式。
    
        


### zip2john

1. what?

    将ZIP 文件中的密码转换为 John the Ripper 可识别的格式，这样可以使用 John the Ripper 对 ZIP 文件的密码进行破解尝试。它可以提取 ZIP 文件中的加密哈希信息，并将其转换为适用于 John the Ripper 的格式，以便进行暴力破解或使用字典攻击等方法尝试破解密码。

2. 具体实例

    1. zip2john a.zip > hash：会将 `a.zip`的密码进行处理，放入到 `hash`这个文件中。

# 复盘/相关知识

## 复盘

### 跑在18812端口的程序有root权限？

1. 在打靶的过程中，我们进行 `rpc`提权时候(至少我们台靶机)要求在 `18812`端口上的程序必须是有 `root`用户起起来的，不然我在脚本中执行 `sudo usermod -a -G sudo ragnar`是权限不够的。所以在打靶的时候我也是要大胆尝试的，正好命中泡在 `18812`端口上的程序就是有 `root`起的。在打靶结束后我们翻过来验证，确实这样（`lsof`工具需要 `suod`，只有在打靶结束后才能验证 ）

    ![image-20230527101906408](https://image.cchl.fun/kali_image/image-20230527101906408.png)

## 重要 

### sudo组的具体了解

sudo（Superuser Do）是一个权限管理工具，允许系统管理员授予普通用户临时获得超级用户（root）权限的能力。通过 sudo，管理员可以以更安全的方式管理系统，而==无需将 root 密码直接分享给其他用户==。

在 sudo 的配置中，有一个特殊的用户组称为 sudo 组（也称为 wheel 组）。sudo 组中的用户被授予可以使用 sudo 命令的权限。

1. ==创建 sudo 组==：在一些 Linux 发行版中，默认情况下可能没有 sudo 组。在创建 sudo 组之前，管理员需要使用 root 权限创建该组。例如，使用以下命令创建 sudo 组：`groupadd sudo`

2. ==添加用户到 sudo 组==：一旦 sudo 组创建完成，管理员可以将其他用户添加到 sudo 组，以授予他们使用 sudo 命令的权限。

    `usermod -aG sudo <用户名>`

添加用户到 sudo 组后，他们就可以使用 sudo 命令以管理员权限执行特定的命令。

1. ==sudo 配置文件==：sudo 组的权限由 `/etc/sudoers` 文件中的配置定义。管理员可以通过编辑该文件来调整 sudo 组的权限。通常，该文件由 `visudo` 命令打开，该命令会在保存修改后进行语法验证，以确保文件的正确性。

    `visudo  /etc/sudoers`

    在该文件中，管理员可以指定哪些用户组或用户具有使用 sudo 的权限，并定义他们可以执行的命令。

请注意以下几点：

- sudo 组只是一种约定，==可以根据需要更改组名称。在某些系统中，sudo 组可能被称为 wheel 组==。

- 需要注意的是，只有具有适当权限的用户可以将其他用户添加到 sudo 组。这通常需要管理员或 root 权限。

- ==在某些 Linux 发行版中，默认配置允许 sudo 组的成员执行任意命令==，而在其他发行版中可能有更严格的配置限制。

- 使用 sudo 组时，需要==小心配置 sudoers== 文件，确保只授予必要的权限，并避免安全漏洞。

    

### sudo -s 和 su root的区别

1. sudo -s：将启动一个新的 shell，该 shell 的用户身份将变为超级用户，==不需要输入 root 用户的密码，系统将要求你输入当前用户的密码，但是必须拥有sudo权限才使用该命令==。在该 shell 中执行的所有命令都将具有管理员权限。

2. su root：相当于是切换用户，==需要输入 root用户的密码==。

    

### rpyc 

1. what?                                                              [==返回==](#back4)<a id='tag4'></a>   

    在Python中，rpyc（Remote Python Call）模块是一个用于实现远程过程调用的框架。它允许你在不同的计算机之间建立远程连接并调用远程计算机上的函数和方法。

    ==官方文档：==[Part 1: Introduction to Classic RPyC — RPyC](https://rpyc.readthedocs.io/en/latest/tutorial/tut1.html)

2. 大致使用

    1. 服务端要开启一个服务，默认开放的端口为：`18812`
    
        ```bash
        $ python bin/rpyc_classic.py
        INFO:SLAVE/18812:server started on [127.0.0.1]:18812
        ```
    
    2. 客户端也要开启一个服务来连接服务端：
    
        ```python
        import rpyc
        conn = rpyc.classic.connect("localhost")
        ```
    
        默认会连接服务端的 `18812`端口
    
    3. `tleport`  is another interesting method that allows you to transmit functions to the other sides and execute them over there:
    
        ```
        >>> def square(x):
        ...    return x**2
        >>> fn = conn.teleport(square)
        >>> fn(2)
        ```
    
        This calculates the square of two as expected, but the computation takes place on the remote!
        
        

### ~/.profile

1. what?                                                                  [==返回==](#tag8)<a id='back8'></a>

    ​		是一个用于登录 shell 的配置文件，主要用于设置用户的环境变量和执行用户登录时需要执行的命令。是用户级别的配置文件之一，用于设置用户的环境变量和执行其他初始化操作。该文件通常位于用户的主目录下`~/.profile`。

2. 玩法/知识

    1. 用户还可以通过 `.profile` 文件加载其他的配置文件，如 `.bashrc` 或 `.bash_profile`

    2. `.profile` 文件在用户登录时才会执行，如果您修改了该文件，需要重新登录或者执行 `source ~/.profile` 命令来使修改生效

    3. `.profile` 文件只会在登录 shell 中执行一次。如果用户打开新的终端窗口或会话，不会重新执行 `.profile` 文件。对于非登录 shell，可以使用其他配置文件，如 `.bashrc`、`.zshrc` 等。

         

### RPC漏洞

1. what?

    ​			RPC（远程过程调用）漏洞是指由于不正确地实现或配置RPC协议导致的安全漏洞。RPC是一种用于不同计算机之间通信的协议，允许一个计算机上的程序调用另一个计算机上的程序，就像调用本地程序一样。然而，如果RPC协议的实现存在漏洞，攻击者可能利用这些漏洞执行恶意操作或者绕过安全措施
    
    


### PK-->ZIP

1. what?

    当数据流以字母 "PK" 开头时，很可能是 ZIP 文件格式。ZIP 文件的文件头部分包含标识符 "PK"，这是 ZIP 文件格式的标志之一。
