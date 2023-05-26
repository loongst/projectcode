#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pocsuite3.api import (
    minimum_version_required, POCBase, register_poc, requests, logger,
    OptString, OrderedDict,
    random_str,
)
import json
minimum_version_required('2.0.4')


class DemoPOC(POCBase):
    vulID = '0'
    version = '1'
    author = 'xml'
    vulDate = '2023-05-26'
    createDate = '2023-05-26'
    updateDate = '2023-05-26'
    references = []
    name = 'http missing security header'
    appPowerLink = ''
    appName = ''
    appVersion = ''
    vulType = 'Information Disclosure'
    desc = 'Vulnerability description'
    samples = ['']
    install_requires = ['']
    pocDesc = 'User manual of poc'
    dork = {'zoomeye': ''}
    suricata_request = ''
    suricata_response = ''
    security_headers=[
        'referrer-policy',
        'access-control-allow-origin',
        'access-control-max-age',
        'strict-transport-security',
        'clear-site-data',
        'x-permitted-cross-domain-policies',
        'access-control-expose-headers',
        'access-control-allow-methods',
        'permissions-policy',
        'x-frame-options',
        'cross-origin-opener-policy',
        'cross-origin-resource-policy',
        'access-control-allow-credentials',
        'access-control-allow-headers',
        'content-security-policy',
        'cross-origin-embedder-policy',
        'X-Content-Type-Options'
    ]

    def _exploit(self,):

        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        res = requests.get(self.url, headers=headers)
        logger.debug(res.headers)
        if not res.status_code==301 and not res.status_code==302:
            return res.headers

    def _verify(self):
        result = {}
        prt=''
        res = self._exploit()
        res_headers=dict(res).keys()
        for item in self.security_headers:
            if item not in res_headers:
                prt=prt+item+', '
        logger.debug('\n'+prt)    
        if res and len(prt)>30:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['VerifyInfo']['info'] = {}
            result['VerifyInfo']['info']['http-missing-security-headers'] = prt
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
