# CThun
CThun是集成快速端口扫描,服务识别,netbios扫描,网站识别和暴力破解的工具.

# 优点
* 端口扫描扫描速度快(255个IP,TOP100端口,15秒)
* 服务识别准确(集成NMAP指纹数据库)
* 单文件无依赖(方便内网扫描)
* 适应性强(Windows Server 2003,Windows Server 2012,CentOS6,Debain9,ubuntu16)
* 支持多种协议暴力破解
* 支持netbios扫描(获取多网卡ip)
* 支持vul扫描(ms17-010)

# 缺点
* 可执行文件大(20M)

# 依赖
* Postgresql及RDP的暴力破解依赖OpenSSL(Windows Server 2003/Windows XP不能使用这两个暴力破解功能,其他功能无影响)
* Linux服务器需要glibc版本大于2.5(高于centos5,ldd --version查看)

# 漏洞列表
* ms17-010
* CVE_2019_3396
* CVE_2017_12149
* S2_015
* S2_016
* S2_045
* CVE_2017_12615
* CVE_2017_10271
* CVE_2018_2894
* CVE_2019_2729


# 使用方法
* 将可执行文件chton.exe上传到已控制主机
* chtun -h 查看帮助信息

# 命令样例
## 使用端口扫描结果进行后续操作
* 扫描192.168.3.1的C段和192.168.4.1-10,192.168.5.1-2的top100端口和33899,33900,33901端口,结果会保存到XXX_result.log文件中
```
cthun.exe -ips 192.168.3.1/24,192.168.4.1-192.168.4.10,192.168.5.1,192.168.5.2  -tp 100 -p 33899-33901
```
* 扫描ip.txt中的ip地址的top100端口和33899,33900,33901端口,结果会保存到XXX_result.log文件中
```
cthun.exe -ipf ip.txt  -tp 100 -p 33899-33901
```
* 端口扫描完成后针对http(s)服务进行增强扫描
```
cthun.exe -ips 192.168.3.1/24,192.168.4.1-192.168.4.10,192.168.5.1,192.168.5.2 -tp 100 -p 33899-33901 -hs
```
* 端口扫描完成后针对smb和rdp服务进行暴力破解,不使用内置字典只使用自定义字典
```
cthun.exe -ips 192.168.3.1/24,192.168.4.1-192.168.4.10,192.168.5.1,192.168.5.2 -tp 100 -p 33899-33901 -bf smb,rdp -nd
```
* 端口扫描完成后针对ftp, ssh, rdp, smb, mysql, mssql, redis, mongodb, memcached,postgresql, vnc服务进行暴力破解,使用内置字典和自定义字典
```
cthun.exe -ips 192.168.3.1/24,192.168.4.1-192.168.4.10,192.168.5.1,192.168.5.2 -tp 100 -p 33899-33901 -bf all 
```

* 针对指定ip范围进行netbios扫描
```
cthun.exe -ips 192.168.3.1/24,192.168.4.1-192.168.4.10,192.168.5.1,192.168.5.2 -nbs 
```


##不使用端口扫描,直接读取txt或log文件中ip和端口进行后续操作


* 使用smb.txt中的ip地址范围,使用hashes.txt中的hash,使用user.txt中的用户名,使用password.txt中的密码,使用domain.txt中的windows域名,不使用内置字典进行smb协议暴力破解
```
cthun.exe -bf smb -nd
```

* 使用ipportservice.log(端口扫描自动生成的日志文件)中的ip,端口,服务,使用hashes.txt中的hash,使用user.txt中的用户名,使用password.txt中的密码,使用domain.txt中的windows域名,不使用内置字典进行smb协议暴力破解
```
cthun.exe -lf -bf smb -nd
```

* 使用ssh.txt中的ip地址范围,使用user.txt中的用户名,使用password.txt中的密码,使用文件id_rsa_1及id_rsa_2作为私钥,不使用内置字典进行ssh协议暴力破解
```
cthun.exe -bf ssh -nd -sshkeys id_rsa_1,id_rsa_2
```

* 使用http.txt中的ip地址范围,进行http扫描并定位网站包含proxy.jsp,ant.jsp,shell.php等url
```
cthun.exe -hs -hs-url proxy.jsp,ant.jsp,shell.php
```
* 使用smb.txt,http.txt,https.txt中的ip地址范围,进行ms17-010,struts2,weblogic,tomcat,jboss的vul扫描
```
cthun.exe -vs
```


## txt文件内容样例

* smb.txt
```
192.168.3.10:445
192.168.4.1/24
```
* hashes.txt
```
testdomain,administrator,aad4b435b51404eeaad3b435b51404ee:8bc3aeb7e2691d071dd14a3b998e9bf7
testdomain,domainadmin1,aad4b435b51404eeaad3b435b5140412:8bc3aeb7e2691d071dd14a3b998e9b12
```
* user.txt(空行表示空用户)
```

root
ftp
administrator
sa
mongo
system
memcache
postgres
```
* pass.txt(空行表示空密码)
```

vncpasss
toor
ftp
123qwe!@#!@
123qwe!@#
mysqlpass
my-secret-pw
123qwe!@#
foobared
mongo
memcache
password
test
```
* domain.txt
```
sealgod
testdomain
```

* http.txt
```
192.168.3.10-192.168.3.12:80
192.168.3.10:8080
192.168.3.10:82
192.168.3.10:444
```

# 已测试
* Windows server 2003
* Windows7
* Windows Server 2012
* CentOS5
* Kali
# 工具截图
![图片](https://uploader.shimo.im/f/jxgOCMlyvbMEnsig.png!thumbnail)
![图片](https://uploader.shimo.im/f/djUIDtYzRI8gh2a8.png!thumbnail)

# 更新日志
**1.0 beta**
更新时间: 2019-09-04
* 增加暴力破解功能

**1.1**
更新时间: 2019-09-11
* 修复windows server 2003 无法打开问题
* linux依赖降低到glibc2.12版本
* 端口扫描支持输入范围(1-65535全端口)
* 暴力破解模块支持指定需要破解的协议
* 更快捷的命令行参数
* 新增http(s)服务增强扫描,获取title,status_code,网站组件等信息
* 端口扫描输出格式更加友好

**1.1.1**
更新时间: 2019-09-11
* MongoDB增加未授权检测
* redis新增 foobared默认密码
**1.1.2**
更新时间: 2019-10-11
* 修复ssh暴力破解输出无效日志

**1.1.3**
更新时间: 2019-11-09
* 修复ssh暴力破解输出无效日志
* 修复运行范围过大时出现 Memory Error错误
* 修复显示扫描端口范围时在输入1-65535时出现过长问题

**1.1.4**
更新时间: 2019-11-14
* 支持单个ip输入,C段输入,ip范围输入,从文件中输入ip列表

**1.1.5**
更新时间: 2019-11-19
* 增加重试参数,增强准确性
**1.1.6**
更新时间: 2019-11-20
* 支持不经过端口扫描,直接读取ssh.txt(或rdp,redis等等)中ip端口进行暴力破解

**1.1.7**
更新时间: 2019-12-02
* 添加weblogic T3协议指纹
* 添加默认http协议指纹
**1.1.8**
更新时间: 2019-12-04
* 修改输出日志文件名,每次扫描输出一个日志文件
* 增加扫描完成后写入扫描结束时间到单独文件,便于观察那些任务完成了

**1.1.9**
更新时间: 2019-12-11
* 增加netbios扫描
* 优化ssh暴力破解,支持输入RSA私钥进行暴力破解
* 优化smb暴力破解,支持hash暴力破解,支持输入domain
* 优化http扫描,支持定位网站是否包含指定url
* 新增vul扫描,当前支持ms17-010扫描
* linux依赖降低到glibc2.5版本

**1.2.0**
更新时间: 2019-12-22
* 增加http的vulscan
* 优化端口扫描部分,当前会保存所有历史记录到ipportservice.log,可以使用-lf命令加载该记录


cthun(克苏恩)是魔兽世界电子游戏中一位上古之神

