import base64
from typing import OrderedDict
from urllib.parse import urljoin
import platform
from pocsuite3.api import Output, POCBase, register_poc, requests, logger,OptString
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str
from requests.exceptions import ReadTimeout
import paramiko
import os
from time import sleep

class DemoPOC(POCBase):
    vulID = '0'  # Seebug 漏洞收录 ID，如果没有则为 0
    version = '1.0'  # PoC 的版本，默认为 1
    author = 'xml'  # PoC 的作者
    vulDate = '2021-8-18'  # 漏洞公开日期 (%Y-%m-%d)
    createDate = '2021-8-20'  # PoC 编写日期 (%Y-%m-%d)
    updateDate = '2021-8-20'  # PoC 更新日期 (%Y-%m-%d)
    references = ['https://www.seebug.org/vuldb/ssvid-99335']  # 漏洞来源地址，0day 不用写
    name = 'Host scan'  # PoC 名称，建议命令方式：<厂商> <组件> <版本> <漏洞类型> <cve编号>
    appPowerLink = ''  # 漏洞厂商主页地址
    appName = 'Host vulnerabilities'  # 漏洞应用名称
    appVersion = 'v1.0'  # 漏洞影响版本
    vulType = 'Code Execution'  # 漏洞类型，参见漏洞类型规范表
    desc = '对目标主机进行安全配置扫描'  # 漏洞简要描述
    samples = ['http://192.168.1.1']  # 测试样列，就是用 PoC 测试成功的目标
    install_requires = ['paramiko']  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    pocDesc = ''' pocsuite -r Hostscanner.py -u ip:prot --username xxx --password xxx --verify '''
    category = "POC_CATEGORY.EXPLOITS.WEBAPP"  # PoC 的分类
    protocol = "ssh"  # PoC 的默认协议，方便对 url 格式化
    protocol_default_port = 22  # 目标的默认端口，当提供的目标不包含端口的时候，方便对 url 格式化
    # dork = {'zoomeye': 'deviceState.admin.hostname'}  # 搜索 dork，如果运行 PoC 时不提供目标且该字段不为空，将会调用插件从搜索引擎获取目标。
    rport=22
    # username="monitor"
    # password="1qaz!QAZ"
    def _options(self):
        o=OrderedDict()
        o["username"]=OptString('')
        o["password"]=OptString('')
        return o

    def rcmd(self,command=None,host=None,port=22):
        username=self.get_option("username")
        password=self.get_option("password")
        try:
            ssh=paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(hostname=host, username=username, password=password, port=port)
            try:
                _stdin, _stdout, _stderr = ssh.exec_command(command)
                bash_out = _stdout.readlines()
                bash_err = _stderr.read()
                if bash_err:
                    save_err = '[%s] bash input: %s, ERROR:\n%s' % (host, command, bash_err) + "\n"
                    logger.error(save_err)
                if bash_out:
                    return bash_out
            except Exception as ssh_err:
                save_err = '[%s] bash ERROR:\n%s' % (host, ssh_err) + "\n"
                logger.error(save_err)
                return False
            finally:
                ssh.close()
        except Exception as ssh_err:
            save_err = '[%s] bash ERROR:\n%s' % (host, ssh_err) + "\n"
            logger.error(save_err)
            return False

    def uploadfile(self,localfilepath,remotefilepath):
        username=self.get_option("username")
        password=self.get_option("password")
        try:
            t=paramiko.Transport((self.rhost,self.rport))
            t.connect(username=username,password=password)
            sftp=paramiko.SFTPClient.from_transport(t)
            logger.info("upload file start!")
            sftp.put(localpath=localfilepath,remotepath=remotefilepath)
            sleep(5)
            sftp.close()
            t.close()
            logger.info("upload file ended!")
        except Exception as e:
            logger.error(e)


    def downloadfile(self,localfilepath,remotefilepath):
        username=self.get_option("username")
        password=self.get_option("password")
        try:
            t=paramiko.Transport((self.rhost,self.rport))
            t.connect(username=username,password=password)
            sftp=paramiko.SFTPClient.from_transport(t)
            print("upload file start")
            sftp.get(localpath=localfilepath,remotepath=remotefilepath)
            sleep(5)
            sftp.close()
            t.close()
        except Exception as e:
            print(e)



    
    def _verify(self):
        username=self.get_option("username")
        password=self.get_option("password")
        result={}
        basepath=os.path.split(os.path.realpath(__file__))[0]
        logger.info("blscan location:{}".format(basepath))
        if "windows"==platform.uname().system:
            self.uploadfile(basepath+r"\blscan.sh","blscan.sh")
        else:
            self.uploadfile(basepath+r"/blscan.sh","blscan.sh")
        cmdresult=self.rcmd(command="bash blscan.sh",host=self.rhost)

        results=self.rcmd(command="cat check.log",host=self.rhost)
        cmdresult=self.rcmd(command="rm -rf blscan.sh ckeck.log",host=self.rhost)
        logger.info("Delete the generated file!")
        if results:
            result['info']={}
            result['info']['host']=self.rhost
            result['info']['result']='\n'+''.join(results)
            return self.parse_output(result)
            
    def _attack(self):
        return self._verify()

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('check faild!')
        return output




register_poc(DemoPOC)

