#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pocsuite3.api import (
    minimum_version_required, POCBase, register_poc, requests, logger,
    OptString, OrderedDict,
    random_str,
)
import time
import re
import sys
import os
import socket
import optparse
from concurrent.futures import ThreadPoolExecutor,as_completed
from colorama import init, Fore
minimum_version_required('2.0.2')

init()
GREEN = Fore.GREEN
RESET = Fore.RESET
GRAY = Fore.LIGHTBLACK_EX

class DemoPOC(POCBase):
    vulID = '0'
    version = '1'
    author = 'xml'
    vulDate = '2023-03-28'
    createDate = '2023-03-28'
    updateDate = '2023-03-28'
    references = []
    name = 'port scan'
    appPowerLink = ''
    appName = ''
    appVersion = ''
    vulType = 'Other'
    desc = 'Vulnerability description'
    samples = ['']
    install_requires = ['']
    pocDesc = 'User manual of poc'
    dork = {'zoomeye': ''}
    suricata_request = ''
    suricata_response = ''
    severity='high'
    pwd = os.path.abspath(os.path.dirname(__file__))
    nmap_file = os.path.join(pwd, "nmap-services.txt")
    NMAP_SERVICES = open(nmap_file).read().splitlines()

    OUTPUT_TEMPLATE = "{lines}"

    # def _options(self):
    #     o = OrderedDict()
    #     o['startIP'] = OptString('', description='startIP',require=False)
    #     o['endIP']= OptString('', description='The endIP',require=False)
    #     return o
    

    def lookup_service(self,port):
        for line in self.NMAP_SERVICES:
            if f"{port}/tcp" in line:
                return line.split()[0]


    def generate_output(self,raw_data):
        # raw_data = [(22, 'closed'), (23, 'open'), ...]
        lines = list()
        for raw in raw_data:
            p, state = raw
            service = self.lookup_service(p)
            port = f"{p}/tcp"
            lines.append(f"{GREEN}{port:<9} {state:<6} {service}")
        return self.OUTPUT_TEMPLATE.format(lines="\n".join(lines))

    def parse(self,output):
        parsed_output = list()
        for line in output.split("\n"):
            if "/tcp" in line or "/udp" in line:
                port_str, state, service = line.split()
                port, protocol = port_str.split("/")
                parsed_output.append(
                    {
                        "port": port,
                        "state": state,
                        "service": service,
                        "protocol": protocol,
                    }
                )
        return parsed_output


    def ip2num(self,ip):
        ip = [int(x) for x in ip.split('.')]
        return ip[0] << 24 | ip[1] << 16 | ip[2] << 8 | ip[3]
        
    def num2ip(self,num):
        return '%s.%s.%s.%s' % ((num & 0xff000000) >> 24,
                                (num & 0x00ff0000) >> 16,
                                (num & 0x0000ff00) >> 8,
                                num & 0x000000ff)


    #输入到结束
    def ip_range(self,start, end):
        return [self.num2ip(num) for num in range(self.ip2num(start), self.ip2num(end) + 1) if num & 0xff]
    
    def scan_open_port_server(self,host,port):
        raw_data = list()
        host,port=host,port
        ss=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ss.settimeout(0.2)
        try:
            result=ss.connect_ex((host,port))
            if result==0:
                raw_data.append((port, "open"))
                raw_output = self.generate_output(raw_data)
                print(raw_output)
                return raw_output.strip('\x1b[32m')
            else:
                pass
            ss.close()
        except Exception as e:
            print(e)
            pass

    def _exploit(self, param=''):
        out=[]
        startIp =self.url.strip("http://").strip("https://").strip("/")
        startIp=startIp.split(":")[0]
        endIp = startIp
        PORT={}
        for line in self.NMAP_SERVICES[24:]:
            PORT[int(line.split()[1].split('/')[0])]="{}".format(line.split()[0])

        starttime=time.time()

        iplist = self.ip_range(startIp, endIp)
        print ('端口采用默认扫描请自行进行比对:\nbegin Scan '+str(len(iplist))+" ip...")

        OUTPUT_TEMPLATE2 = "PORT      STATE  SERVICE"
        print(OUTPUT_TEMPLATE2)
        obj_list=[]
        with ThreadPoolExecutor(max_workers=300) as pool:
            for host in iplist:
                for port in PORT.keys():
                    obj=pool.submit(self.scan_open_port_server,host,port)
                    obj_list.append(obj)
            
            for future in as_completed(obj_list):
                if future.result():
                    out.append(future.result())

        # print('All RUN TIME：'+str(time.time()-starttime))

        return '\n'.join(out)

    def _verify(self):
        result = {}
        param = ''
        res = self._exploit(param)

        if res:
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
