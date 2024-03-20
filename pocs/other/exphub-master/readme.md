# Notice
~~终究还是觉得每个漏洞每个单独的脚本很不方便，故将所有的poc和exp脚本整在一起，可以一键扫描+漏洞利用，由于近期都在做整合所以exphub搁置许久没有更新，目前整合版已经接近尾声，将在10月发布（节后），敬请关注~~  
已经发布 --->  https://github.com/zhzyker/vulmap

# Exphub
Exphub[漏洞利用脚本库] （想要star⭐~)  
目前包括Webloigc、Struts2、Tomcat、Drupal的漏洞利用脚本，均为亲测可用的脚本文件，尽力补全所有脚本文件的使用说明文档，优先更新高危且易利用的漏洞利用脚本  
部分脚本或文件是搜集的，若有版权要求联系即改  
鹅群：219291257  
bilibili：https://space.bilibili.com/64648363

最后更新：2021/04/04，最新添加 **cve-2021-26295_rce.py**

# Readme
Exphub包括多种不同名称、类型、格式、后缀的文件，这些文件可以大致分为[漏洞验证脚本]、[漏洞利用脚本]、[远程命令执行脚本]、[shell交互脚本]、[Webshell上传脚本]  
脚本文件示例：cve-1111-1111_xxxx.py  

脚本文件种类[xxxx]:  
- cve-1111-1111_**poc** [漏洞验证脚本] 仅检测验证漏洞是否存在
- cve-1111-1111_**exp** [漏洞利用脚本] 例如文件包含、任意文件读取等常规漏洞，具体每个脚本使用另参[使用]
- cve-1111-1111_**rce** [远程命令执行脚本] 命令执行漏洞利用脚本，无法交互  
- cve-1111-1111_**cmd** [远程命令执行脚本] 命令执行漏洞利用脚本，无法交互
- cve-1111-1111_**shell** [远程命令执行脚本] 直接反弹Shell，或者提供简单的交互Shell以传递命令,基础交互
- cve-1111-1111_**webshell** [Webshell上传脚本] 自动或手动上传Webshell  

脚本文件格式[py]:  
- cve-xxxx.**py** Python文件，包括py2和py3，具体哪个文件是哪个版本参照说明(执行即可见)，推荐py2.7和py3.7
- cve-xxxx.**sh** Shell脚本，需要Linux环境运行，执行即见说明，无发行版要求
- cve-xxxx.**jar** Java文件，执行方式均为`java -jar cve-xxxx.jar`,推荐Java1.8.121
- cve-xxxx.**php** PHP文件，直接使用`php`命令执行即可
- cve-xxxx.**txt** 无法编写成可执行文件的漏洞Payload，将直接写成txt文本，文本内记录如何使用(一般为GET/POST请求

## Fastjson
[**fastjson-1.2.24_rce.py**](https://github.com/zhzyker/exphub/tree/master/fastjson) Fastjson <=1.2.24 反序列化远程命令执行漏洞  
[**fastjson-1.2.41_rce.py**](https://github.com/zhzyker/exphub/tree/master/fastjson) Fastjson <=1.2.41 反序列化远程命令执行漏洞  
[**fastjson-1.2.42_rce.py**](https://github.com/zhzyker/exphub/tree/master/fastjson) Fastjson <=1.2.42 反序列化远程命令执行漏洞  
[**fastjson-1.2.43_rce.py**](https://github.com/zhzyker/exphub/tree/master/fastjson) Fastjson <=1.2.43 反序列化远程命令执行漏洞  
[**fastjson-1.2.45_rce.py**](https://github.com/zhzyker/exphub/tree/master/fastjson) Fastjson <=1.2.45 反序列化远程命令执行漏洞  
[**fastjson-1.2.47_rce.py**](https://github.com/zhzyker/exphub/tree/master/fastjson) Fastjson <=1.2.47 反序列化远程命令执行漏洞[[使用]](https://freeerror.org/d/512)  
[**fastjson-1.2.62_rce.py**](https://github.com/zhzyker/exphub/tree/master/fastjson) Fastjson <=1.2.62 反序列化远程命令执行漏洞  
[**fastjson-1.2.66_rce.py**](https://github.com/zhzyker/exphub/tree/master/fastjson) Fastjson <=1.2.66 反序列化远程命令执行漏洞  

## Weblogic
[**cve-2014-4210_ssrf_scan.py**](https://github.com/zhzyker/exphub/blob/master/weblogic/) Weblogic SSRF 扫描内网端口利用脚本 [[使用]](https://freeerror.org/d/483)  
[**cve-2014-4210_ssrf_redis_shell.py**](https://github.com/zhzyker/exphub/blob/master/weblogic/) Weblogic SSRF漏洞内网redis未授权getshell脚本[[使用]](https://freeerror.org/d/483)  
[**cve-2017-3506_poc.py**](https://github.com/zhzyker/exphub/blob/master/weblogic/) Weblogic wls-wsat 远程命令执行漏洞检测脚本[[使用]](https://freeerror.org/d/468)  
[**cve-2017-3506_webshell.jar**](https://github.com/zhzyker/exphub/blob/master/weblogic/) Weblogic wls-wsat 远程命令执行漏洞利用，上传Webshell[[使用]](https://freeerror.org/d/468)  
[**cve-2017-10271_poc.jar**](https://github.com/zhzyker/exphub/blob/master/weblogic/) Weblogic wls-wsat XMLDecoder 反序列化漏洞[[使用]](https://freeerror.org/d/460)  
[**cve-2017-10271_webshell.jar**](https://github.com/zhzyker/exphub/blob/master/weblogic/) Weblogic wls-wsat XMLDecoder 反序列化漏洞利用脚本[[使用]](https://freeerror.org/d/460)  
[**cve-2018-2628_poc.py**](https://github.com/zhzyker/exphub/blob/master/weblogic/) Weblogic WLS Core Components 反序列化命令执行漏洞验证脚本[[使用]](https://freeerror.org/d/464)  
[**cve-2018-2628_webshell.py**](https://github.com/zhzyker/exphub/blob/master/weblogic/) 	Weblogic WLS Core Components 命令执行漏洞上传Webshell脚本[[使用]](https://freeerror.org/d/464)  
[**cve-2018-2893_poc.py**](https://github.com/zhzyker/exphub/blob/master/weblogic/) WebLogic WLS 核心组件反序列化漏洞检测脚本  
[**cve-2018-2893_cmd.py**](https://github.com/zhzyker/exphub/blob/master/weblogic/) WebLogic WLS 核心组件反序列化漏洞利用脚本  
[**cve-2018-2894_poc_exp.py**](https://github.com/zhzyker/exphub/blob/master/weblogic/)	Weblogic 任意文件上传漏洞检测+利用  
[**cve-2019-2618_webshell.py**](https://github.com/zhzyker/exphub/blob/master/weblogic/) Weblogic 任意文件上传漏洞(需要账户密码)[[使用]](https://freeerror.org/d/469)  
[**cve-2020-2551_poc.py**](https://github.com/zhzyker/exphub/blob/master/weblogic/) Weblogic IIOP 反序列化漏洞检测脚本  
[**cve-2020-2555_cmd.py**](https://github.com/zhzyker/exphub/blob/master/weblogic/) WebLogic GIOP 协议反序列化远程命令执行  
[**cve-2020-2883_cmd.py**](https://github.com/zhzyker/exphub/blob/master/weblogic/) WebLogic T3 协议反序列化远程命令执行  
[**cve-2020-14882_rce.py**](https://github.com/zhzyker/exphub/blob/master/weblogic/) WebLogic console 未授权命令执行

## Shiro
[**shiro-1.2.4_rce.py**](https://github.com/zhzyker/exphub/tree/master/shiro) Apache Shiro rememberMe < 1.2.4 RCE exploit script  

## Solr
[**cve-2017-12629_cmd.py**](https://github.com/zhzyker/exphub/tree/master/solr) Apache Solr 远程命令执行脚本  
[**cve-2019-0193_cmd.py**](https://github.com/zhzyker/exphub/tree/master/solr) Apache Solr DataImportHandler 远程代码执行漏洞利用脚本  
[**cve-2019-17558_cmd.py**](https://github.com/zhzyker/exphub/tree/master/solr) Apache Solr Velocity远程代码执行漏洞利用脚本[[视频_Bilibili]](https://www.bilibili.com/video/BV1jf4y12749) [[视频_YouTube]](https://www.youtube.com/watch?v=WP81oOl2AgU)  

## Spring
[**cve-2018-1273_cmd.py**](https://github.com/zhzyker/exphub/tree/master/spring) Spring 远程代码执行漏洞利用脚本  

## Struts2
[**struts2-032_cmd.py**](https://github.com/zhzyker/exphub/blob/master/struts2)	Struts2 method 任意代码执行漏洞GetShell利用脚本(CVE-2016-3081)  
[**struts2-032_poc.py**](https://github.com/zhzyker/exphub/blob/master/struts2)	Struts2 method 任意代码执行漏洞检测脚本(CVE-2016-3081)    
[**struts2-045_cmd.py**](https://github.com/zhzyker/exphub/blob/master/struts2)	Struts2 Jakarta Multipart parser 插件远程命令执行漏洞利用脚本1(CVE-2017-5638)[[使用]](https://freeerror.org/d/490)  
[**struts2-045-2_cmd.py**](https://github.com/zhzyker/exphub/blob/master/struts2)	Struts2 Jakarta Multipart parser 插件远程命令执行漏洞利用脚本2(CVE-2017-5638)[[使用]](https://freeerror.org/d/490)  
[**struts2-052_cmd.py**](https://github.com/zhzyker/exphub/blob/master/struts2) Struts2 REST 插件远程代码执行漏洞利用脚本(CVE-2017-9805)  
[**struts2-052_webshell.py**](https://github.com/zhzyker/exphub/blob/master/struts2) Struts2 REST 插件远程代码执行漏洞上传Webshell脚本(CVE-2017-9805)  
[**struts2-053_cmd.py**](https://github.com/zhzyker/exphub/blob/master/struts2) Struts2 Freemarker 标签远程执行命令漏洞利用脚本(CVE-2017-12611)  
[**struts2-057_cmd.py**](https://github.com/zhzyker/exphub/blob/master/struts2) Struts2 Namespace 远程代码执行漏洞利用脚本(CVE-2018-11776)  

## Tomcat
[**cve-2017-12615_cmd.py**](https://github.com/zhzyker/exphub/blob/master/tomcat/) Tomcat 远程代码执行漏洞利用脚本[[使用]](https://freeerror.org/d/411)  
[**cve-2020-1938_exp.py**](https://github.com/zhzyker/exphub/blob/master/tomcat/) Tomcat 幽灵猫任意文件读取漏洞利用脚本[[使用]](https://freeerror.org/d/484)  

## Drupal
[**cve-2018-7600_cmd.py**](https://github.com/zhzyker/exphub/tree/master/drupal) Drupal Drupalgeddon 2 远程代码执行漏洞利用脚本[[使用]](https://freeerror.org/d/426)  
[**cve-2018-7600_poc.py**](https://github.com/zhzyker/exphub/tree/master/drupal) 该脚本可检测 CVE-2018-7602 和 CVE-2018-7600  
[**cve-2018-7602_cmd.py**](https://github.com/zhzyker/exphub/tree/master/drupal) Drupal 内核远程代码执行漏洞利用脚本(需要账户密码)  
[**cve-2018-7602_poc.py**](https://github.com/zhzyker/exphub/tree/master/drupal) 该脚本可检测 CVE-2018-7602 和 CVE-2018-7600  
[**cve-2019-6340_cmd.py**](https://github.com/zhzyker/exphub/tree/master/drupal) Drupal 8.x REST RCE 远程执行代码漏洞利用脚本 

## F5
[**cve-2020-5902_file.py**](https://github.com/zhzyker/exphub/tree/master/f5) F5 BIG-IP 任意文件读取  

## Nexus
[**cve-2019-7238_cmd.py**](https://github.com/zhzyker/exphub/tree/master/nexus/) Nexus Repository Manager 3 远程代码执行漏洞利用脚本  
[**cve-2020-10199_poc.py**](https://github.com/zhzyker/exphub/tree/master/nexus/) Nexus Repository Manager 3 远程命令执行漏洞检测脚本[[视频_Bilibili]](https://www.bilibili.com/video/BV1uQ4y1P7MA/) [[视频_YouTube]](https://www.youtube.com/watch?v=ocQMDYxTMKk)  
[**cve-2020-10199_cmd.py**](https://github.com/zhzyker/exphub/tree/master/nexus/) Nexus Repository Manager 3 远程代码执行漏洞(可回显)[[视频_Bilibili]](https://www.bilibili.com/video/BV1uQ4y1P7MA/) [[视频_YouTube]](https://www.youtube.com/watch?v=ocQMDYxTMKk)  
[**cve-2020-10204_cmd.py**](https://github.com/zhzyker/exphub/tree/master/nexus/)	Nexus Manager 3 远程命令执行漏洞利用脚本(无回显)[[视频_Bilibili]](https://www.bilibili.com/video/BV1uQ4y1P7MA/) [[视频_YouTube]](https://www.youtube.com/watch?v=ocQMDYxTMKk)  
[**cve-2020-11444_exp.py**](https://github.com/zhzyker/exphub/tree/master/nexus/)	Nexus 3 任意修改admin密码越权漏洞利用脚本[[视频_Bilibili]](https://www.bilibili.com/video/BV1uQ4y1P7MA/) [[视频_YouTube]](https://www.youtube.com/watch?v=ocQMDYxTMKk)  

## Jboss
[**cve-2017-12149_poc.py**](https://github.com/zhzyker/exphub/tree/master/jboss) JBoss 5.x/6.x 反序列化远程代码执行漏洞验证脚本  
[**cve-2017-12149_cmd.py**](https://github.com/zhzyker/exphub/tree/master/jboss) JBoss 5.x/6.x 反序列化远程代码执行漏洞利用脚本  

## OFBiz
[**cve-2021-26295_rce.py**](https://github.com/zhzyker/exphub/blob/master/ofbiz) RMI Deserializes Remote Code Execution  
