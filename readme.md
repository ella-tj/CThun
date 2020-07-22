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
* RDP的暴力破解依赖OpenSSL(Windows Server 2003/Windows XP不能使用rdp暴力破解,其他功能无影响)
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
* 修改param.json中参数
* 将可执行文件cthun.exe及param.json上传到已控制主机
* 直接运行cthun.exe

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

**1.3.0**
更新时间: 2020-06-05
* 使用json文件承载输入参数,更加简便直观


cthun(克苏恩)是魔兽世界电子游戏中一位上古之神

