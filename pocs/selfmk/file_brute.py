#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import subprocess
import re
import os,sys,platform
from time import sleep
import requests
requests.packages.urllib3.disable_warnings
# from fake_useragent import UserAgent
# import win32file
from pocsuite3.api import (
    minimum_version_required, POCBase, register_poc, requests, logger,
    OptString, OrderedDict,
    random_str,
)

minimum_version_required('2.0.1')

class DemoPOC(POCBase):
    vulID = '0'
    version = '1'
    author = 'xml'
    vulDate = '2022-11-26'
    createDate = '2022-11-26'
    updateDate = '2022-11-26'
    references = ['http://loongxu.com']
    name = 'Pre-Auth Path Traversal (none)'
    appPowerLink = ''
    appName = 'Path Traversal'
    appVersion = '1.0'
    vulType = 'Path Traversal'
    desc = 'poc of find unauth path or file'
    samples = ['']
    install_requires = ['']
    pocDesc = 'poc of find unauth path or file'
    dork = {'zoomeye': ''}
    suricata_request = ''
    suricata_response = ''

    def get_url(self):

        sourcecode_path=self.get_option("s")
        if os.path.exists(sourcecode_path):
            logger.info("path of sourcecode:"+sourcecode_path)
        else:
            logger.error("source code path is not exists!")
            return
        os_type=platform.uname().system
        logger.info("os_type:"+os_type)
        if 'Windows'==os_type:
            cmdstr=r'for /r "{}" %i in (*.js) do @echo %i'.format(sourcecode_path)
            # logger.critical(cmdstr)
        else:
            cmdstr=r"find {} -name *.js".format(sourcecode_path)
        proc =  subprocess.Popen(cmdstr,stdout=subprocess.PIPE,shell=True)
        file_list=[i.decode("utf-8").strip() for i in  proc.stdout.readlines()]
        url_reg=re.compile(r"[a-zA-Z0-9:/.]*/[a-zA-Z0-9_.&/]*")
        url=[]
        for file in file_list:
            # i+=1
            # print(str(i)+"-"*100)
            # cmd="cat "+file.decode("utf-8").strip()+"|grep url:"
            # tmp=subprocess.Popen(cmd,stdout=subprocess.PIPE,shell=True)
            # url_list=[i for i in tmp.stdout.readlines()]
            # for i in url_list:
            #     print(i)
            with open(file,"r+",encoding="utf-8") as f:
                url_list=re.findall(url_reg,f.read())
            if url_list:
                url_list=list(set(url_list))
            url.extend(url_list)
        url=list(set(url))
        logger.info("API:{}".format(url))
        basepath=os.path.split(os.path.realpath(__file__))[0]
        logger.info("blscan location:{}".format(basepath))
        if "windows"==platform.uname().system:
           wdpath=basepath+r"\dicc.txt"
        else:
            wdpath=basepath+r"/dicc.txt"
        with open(wdpath,"r+") as f:
            wd_base=f.readlines()
        with open("wordlist.txt","w+") as f:
            for i in url:
                f.write(i+"\n")
            f.write(''.join(wd_base))
        # if os.path.exists('wordlist')
        return


    def Scanner(self):
        out=[]
        headers = {
            "UserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36"
        }
        statuscode=[x for x in range(200,402)]
        with open("wordlist.txt", 'r') as f:
            for line in f.readlines():
                line = line.strip()
                if line.startswith("http"):
                    continue
                else:
                    turl=self.url.strip('/')
                    eurl="{}/{}".format(turl,line)
                    scanning="\r Scanning {:<100}".format(eurl)
                    print(scanning,end="",flush=True)
                response = requests.get(eurl,allow_redirects=False)

                if response.status_code in statuscode:
                    if response.status_code>299 and response.status_code<400:
                        prt="{}  {:<}\t-->\t{}\n".format(str(response.status_code),response.request.url,response.headers['Location'])
                    else:
                        prt="{}  {}\n".format(str(response.status_code),response.request.url)

                    # logger.info(prt)
                    out.append(prt)
        return out

 

    def _options(self):
        o = OrderedDict()
        o['s'] = OptString('', description='The path of sourcode')
        return o


    def _verify(self):
        result = {}
        self.get_url()
        result["result"]= "".join(self.Scanner())
        return self.parse_output(result)

    def _exploit(self):
        return self._verify()

    def _attack(self):
        return self._verify()

    def _shell(self):
        return self._verify()


register_poc(DemoPOC)
