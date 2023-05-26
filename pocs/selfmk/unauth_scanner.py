#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import socket
import pymongo
import requests
import ftplib
from tqdm import tqdm
import sys,os
from concurrent.futures import ThreadPoolExecutor,as_completed
import argparse
import urllib3
import platform
import threading
from ldap3 import Connection, Server, ALL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from collections import OrderedDict

from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, VUL_TYPE
from pocsuite3.api import OptString

from pocsuite3.api import (
    minimum_version_required, POCBase, register_poc, requests, logger,
    OptString, OrderedDict,
    random_str,
)

minimum_version_required('2.0.1')


class DemoPOC(POCBase):
    vulID = '0'
    version = '1'
    author = 'xml'
    vulDate = '2022-11-22'
    createDate = '2022-11-22'
    updateDate = '2022-11-22'
    references = []
    name = 'cfit Pre-Auth Information Disclosure (unauth discovry)'
    appPowerLink = 'https://www.cfit.cn'
    appName = 'cfit'
    appVersion = ''
    vulType = 'Information Disclosure'
    desc = 'unauth scan,support redis,hadoop,docker,CouchDb,ftp,zookeeper,elasticsearch,memcached,mongodb'
    samples = ['']
    install_requires = ['']
    pocDesc = 'User manual of poc'
    dork = {'zoomeye': ''}
    suricata_request = ''
    suricata_response = ''
    severity='high'

    #config
    ActiveMQVuln = "/admin"
    AtlassianCrowdVuln = "/crowd/admin/uploadplugin.action"
    CouchDBVuln = ":5984"
    DockerAPIVuln = ":2375/version"
    DubboVuln = 20880
    DruidVuln = "/druid/index.html"
    ElasticsearchVuln = ":9200/_cat"
    FtpVuln = 21
    HadoopYARNVuln = ":8088/cluster"
    JBossVuln = ":8080/jmx-console/"
    JenkinsVuln = ":8080/script"
    JupyterNotebookVuln = ":8889/tree"
    Kibanavuln = ":5601/app/kibana#"
    KubernetesApiServervuln = ":6443"
    Weblogicvuln = ":7001/console/css/%252e%252e%252fconsole.portal"
    Solrvuln = ":8983/solr/#/"
    Springbootvuln = "/actuator/"
    RabbitMQvuln = "/api/whoami"
    Zabbixvuln = "/latest.php?ddreset=1"
    Redisvuln = 6379
    Rsyncvuln = ":873/"
    Memcachevuln = 11211
    MongoDBvuln = 27017
    Zookeepervuln = 2181
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:61.0) Gecko/20100101 Firefox/61.0'
    }

    RabbitMQheaders = {
        'authorization': 'Basic Z3Vlc3Q6Z3Vlc3Q=',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
    }



    def redis(self):
        result=''
        try:
            socket.setdefaulttimeout(5)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.rhost, 6379))
            s.send(bytes("INFO\r\n", 'UTF-8'))
            results = s.recv(1024).decode()
            if "redis_version" in results:
                result=self.rhost + ":6379 redis未授权"
                # print(self.rhost + ":6379 redis未授权")
            s.close()
            # return self.parse_output(result)
            
        except Exception as e:
            pass
        finally:
            #self.bar.update(1)
            pass
        return result

        

    def mongodb(self):
        result=''
        try:
            conn = pymongo.MongoClient(self.rhost, 27017, socketTimeoutMS=4000)
            dbname = conn.list_database_names()
            result=self.rhost + ":27017 mongodb未授权"
            # print(self.rhost + ":27017 mongodb未授权")
            conn.close()
            
        except Exception as e:
            pass
        finally:
            #self.bar.update(1)
            pass
        #return self.parse_output(result)
        return result

    def memcached(self):
        result=''
        try:
            socket.setdefaulttimeout(5)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.rhost, 11211))
            s.send(bytes('stats\r\n', 'UTF-8'))
            if 'version' in s.recv(1024).decode():
                result=self.rhost + ":11211 memcached未授权"
                # print(self.rhost + ":11211 memcached未授权")
            s.close()
            
        except Exception as e:
            pass
        finally:
            #self.bar.update(1)
            pass
        #return self.parse_output(result)
        return result

    def elasticsearch(self):
        result=''
        try:
            url = 'http://' + self.rhost + ':9200/_cat'
            r = requests.get(url, timeout=5)
            if '/_cat/master' in r.content.decode():
                result=self.rhost + ":9200 elasticsearch未授权"
                # print(self.rhost + ":9200 elasticsearch未授权")
            
        except Exception as e:
            pass
        finally:
            #self.bar.update(1)
            pass
        #return self.parse_output(result)
        return result

    def zookeeper(self):
        result=''
        try:
            socket.setdefaulttimeout(5)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.rhost, 2181))
            s.send(bytes('envi', 'UTF-8'))
            data = s.recv(1024).decode()
            s.close()
            if 'Environment' in data:
                result=self.rhost + ":2181 zookeeper未授权"
                # print(self.rhost + ":2181 zookeeper未授权")
            
        except:
            pass
        finally:
            #self.bar.update(1)
            pass
        #return self.parse_output(result)
        return result

    def ftp(self):
        result=''
        try:
            ftp = ftplib.FTP.connect(self.rhost,21,timeout=5)
            ftp.login('anonymous', 'Aa@12345678')
            result=self.rhost + ":21 FTP未授权"
            # print(self.rhost + ":21 FTP未授权")
            
        except Exception as e:
            pass
        finally:
            #self.bar.update(1)
            pass
        #return self.parse_output(result)
        return result

    def CouchDB(self):
        result=''
        try:
            url = 'http://' + self.rhost + ':5984'+'/_utils/'
            r = requests.get(url, timeout=5)
            if 'couchdb-logo' in r.content.decode():
                result=self.rhost + ":5984 CouchDB未授权"
                # print(self.rhost + ":5984 CouchDB未授权")
                return result
        except Exception as e:
            pass
        finally:
            #self.bar.update(1)
            pass
        #return self.parse_output(result)

    def docker(self):
        result=''
        try:
            url = 'http://' + self.rhost + ':2375'+'/version'
            r = requests.get(url, timeout=5)
            if 'ApiVersion' in r.content.decode():
                result=self.rhost + ":2375 docker api未授权"
                # print(self.rhost + ":2375 docker api未授权")
                
        except Exception as e:
            pass
        finally:
            #self.bar.update(1)
            pass
        #return self.parse_output(result)
        return result

    def Hadoop(self):
        result=''
        try:
            url = 'http://' + self.rhost + ':50070'+'/dfshealth.html'
            r = requests.get(url, timeout=5)
            if 'hadoop.css' in r.content.decode():
                result=self.rhost + ":50070 Hadoop未授权"
                # print(self.rhost + ":50070 Hadoop未授权")
        except Exception as e:
            pass
        finally:
            #self.bar.update(1)
            pass
        #return self.parse_output(result)
        return result


    def ActiveMQ(self):
        result=''
        url = "http://" + self.rhost + self.ActiveMQVuln
        try:
            basicAuth = requests.get(url,self.headers, verify=False, auth=('admin', 'admin'))
            if basicAuth.status_code == 200 and "Version" in basicAuth.text:
                result= url+" [!]ActiveMQ Unauthorized"
        except Exception:
            pass
        finally:
            #self.bar.update(1)
            pass
        return result


    def AtlassianCrowd(self):
        result=''
        url = "http://" + self.rhost + self.AtlassianCrowdVuln
        try:
            vuln = requests.get(url,self.headers, verify=False)
            if vuln.status_code == 400:
                result= url+" [!]AtlassianCrowd Unauthorized(RCE https://github.com/jas502n/CVE-2019-11580)"
        except Exception:
            pass
        finally:
            #self.bar.update(1)
            pass
        return result


    def CouchDB(self):
        result=''
        url = "http://" + self.rhost + self.CouchDBVuln
        try:
            vuln = requests.get(url,self.headers, verify=False)
            if vuln.status_code == 200 and "version" in vuln.text:
                result= url+" CouchDB Unauthorized"
        except Exception:
            pass
        finally:
            #self.bar.update(1)
            pass
        return result


    def DockerAPI(self):
        result=''
        url = "http://" + self.rhost + self.DockerAPIVuln
        try:
            vuln = requests.get(url,self.headers, verify=False)
            if vuln.status_code == 200 and "Version" in vuln.text:
                result= url+" DockerAPI Unauthorized"
        except Exception:
            pass
        finally:
            #self.bar.update(1)
            pass
        return result


    def Dubbo(self):
        result=''
        try:
            socket.setdefaulttimeout(5)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.rhost, self.DubboVuln))
            s.send(bytes("status -l\r\n", 'UTF-8'))
            results = s.recv(1024).decode()
            if "server" in results:
                result=self.rhost+" Dubbo Unauthorized"
            s.close()
        except Exception:
            pass
        finally:
            #self.bar.update(1)
            pass
        return result


    def Druid(self):
        result=''
        url = "http://" + self.rhost + self.DruidVuln
        try:
            vuln = requests.get(url,self.headers, verify=False)
            if vuln.status_code == 200 and "Druid Stat Index" in vuln.text:
                result= url+" Druid Unauthorized"
        except Exception:
            pass
        finally:
            #self.bar.update(1)
            pass
        return result


    def Elasticsearch(self):
        result=''
        url = "http://" + self.rhost + self.ElasticsearchVuln
        try:
            vuln = requests.get(url,self.headers, verify=False)
            if vuln.status_code == 200 and "/_cat/master" in vuln.text:
                result= url+" Elasticsearch Unauthorized"
        except Exception:
            pass
        finally:
            #self.bar.update(1)
            pass
        return result


    def Ftp(self):
        result=''
        try:
            ftp = ftplib.FTP()
            ftp.connect(self.rhost, self.FtpVuln)
            ftp.login("anonymous", "anonymous")
            result=self.rhost+" FTP Unauthorized"
        except Exception:
            pass
        finally:
            #self.bar.update(1)
            pass
        return result


    def HadoopYARN(self):
        result=''
        url = "http://" + self.rhost + self.HadoopYARNVuln
        try:
            vuln = requests.get(url,self.headers, verify=False)
            if vuln.status_code == 200 and "All Applications" in vuln.text:
                result= url+" HadoopYARN Unauthorized"
        except Exception:
            pass
        finally:
            #self.bar.update(1)
            pass
        return result


    def JBoss(self):
        result=''
        url = "http://" + self.rhost + self.JBossVuln
        try:
            vuln = requests.get(url,self.headers, verify=False)
            if vuln.status_code == 200 and "JBoss JMX Management Console" in vuln.text:
                result= url+" JBoss Unauthorized"
        except Exception:
            pass
        finally:
            #self.bar.update(1)
            pass
        return result


    def Jenkins(self):
        result=''
        url = "http://" + self.rhost + self.JenkinsVuln
        try:
            vuln = requests.get(url,self.headers, verify=False)
            if vuln.status_code == 200 and "Jenkins-Crumb" in vuln.text:
                result= url+" Jenkins Unauthorized"
        except Exception:
            pass
        finally:
            #self.bar.update(1)
            pass
        return result


    def JupyterNotebook(self):
        result=''
        url = "http://" + self.rhost + self.JupyterNotebookVuln
        try:
            vuln = requests.get(url,self.headers, verify=False)
            if vuln.status_code == 200 and "Jupyter Notebook" in vuln.text:
                result= url+" JupyterNotebook Unauthorized"
        except Exception:
            pass
        finally:
            #self.bar.update(1)
            pass
        return result


    def Kibana(self):
        result=''
        url = "http://" + self.rhost + self.Kibanavuln
        try:
            vuln = requests.get(url,self.headers, verify=False)
            if vuln.status_code == 200 and "Visualize" in vuln.text:
                result= url+" Kibana Unauthorized"
        except Exception:
            pass
        finally:
            #self.bar.update(1)
            pass
        return result


    def KubernetesApiServer(self):
        result=''
        url = "http://" + self.rhost + self.KubernetesApiServervuln
        try:
            vuln = requests.get(url,self.headers, verify=False)
            if vuln.status_code == 200 and "paths" in vuln.text and "/api" in vuln.text:
                result= url+" KubernetesApiServer"
        except Exception:
            pass
        finally:
            #self.bar.update(1)
            pass
        return result


    def ldap_anonymous(self):
        result=''
        try:
            server = Server(self.rhost, get_info=ALL, connect_timeout=1)
            conn = Connection(server, auto_bind=True)
            result="[+] ldap login for anonymous"
            conn.closed()
        except Exception:
            pass
        finally:
            #self.bar.update(1)
            pass
        return result


    def Weblogic(self):
        result=''
        url = "http://" + self.rhost + self.Weblogicvuln
        try:
            vuln = requests.get(url,self.headers, verify=False)
            if vuln.status_code == 200 and "管理控制台主页" in vuln.text and "注销" in vuln.text:
                result= url+" Weblogic Unauthorized"
        except Exception:
            pass
        finally:
            #self.bar.update(1)
            pass
        return result


    def Solr(self):
        result=''
        url = "http://" + self.rhost + self.Solrvuln
        try:
            vuln = requests.get(url,self.headers, verify=False)
            if vuln.status_code == 200 and "Collections" in vuln.text and "Cloud" in vuln.text:
                result= url+" Solr Unauthorized"
        except Exception:
            pass
        finally:
            #self.bar.update(1)
            pass
        return result


    def Springboot(self):
        result=''
        try:
            url = "http://" + self.rhost + self.Springbootvuln
            vuln = requests.get(url,self.headers, verify=False)
            if vuln.status_code == 200 and "/info" in vuln.text and "/health" in vuln.text:
                result= url+" SpringbootActuator Unauthorized"
        except Exception:
            pass
        finally:
            #self.bar.update(1)
            pass
        return result


    def RabbitMQ(self):
        result=''
        url = "http://" + self.rhost + self.RabbitMQvuln
        try:
            vuln = requests.get(url, headers=self.RabbitMQheaders, verify=False)
            if vuln.status_code == 200 and "guest" in vuln.text:
                result= url+" RabbitMQ Unauthorized"
        except Exception:
            pass
        finally:
            #self.bar.update(1)
            pass
        return result


    def Zabbix(self):
        result=''
        url = "http://" + self.rhost + self.Zabbixvuln
        try:
            vuln = requests.get(url, headers=self.RabbitMQheaders, verify=False)
            if vuln.status_code == 200 and "Latest data" in vuln.text:
                result= url+" RabbitMQ Unauthorized"
        except Exception:
            pass
        finally:
            #self.bar.update(1)
            pass
        return result


    def Redis(self):
        result=''
        try:
            socket.setdefaulttimeout(10)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.rhost, self.Redisvuln))
            s.send(bytes("INFO\r\n", 'UTF-8'))
            results = s.recv(1024).decode()
            if "redis_version" in results:
                result=self.rhost+" Redis Unauthorized"
            s.close()
        except Exception:
            pass
        finally:
            #self.bar.update(1)
            pass
        return result


    def Rsync(self):
        result=''
        if "Linux" in platform.platform():
            try:
                rsynctext = "rsync  " + "rsync://" + self.rhost + self.Rsyncvuln
                results = os.popen(rsynctext).read()
                bool = False
                for line in results:
                    if "Password:" in line:
                        bool = True
                        return
                if bool:
                    result=self.rhost+" Rsync Unauthorized"
            except Exception as e:
                logger.error(e)
            finally:
                #self.bar.update(1)
                pass
        else:
            logger.error("[*] Windows does not support Rsync unauthorized scanning")
        
        return result

    def NFS(self):
        result=''
        if "Linux" in platform.platform():
            try:
                rsynctext = "showmount  -e  " + self.rhost
                results = os.popen(rsynctext).read()
                for line in results:
                    if "Export list" in line:
                        result=self.rhost+" NFS Unauthorized"
                    else:
                        logger.error("")
            except Exception as e:
                logger.error(e)

        else:
            logger.error("[*] Windows does not support NFS unauthorized scanning")
        #self.bar.update(1)
        pass
        return result

    def Memcache(self):
        result=''
        try:
            socket.setdefaulttimeout(10)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.rhost, self.Memcachevuln))
            s.send(bytes("stats\r\n", 'UTF-8'))
            results = s.recv(1024).decode()
            if "STAT version" in results:
                result=self.rhost+" Memcachevuln Unauthorized"
            s.close()
        except Exception:
            pass
        finally:
            #self.bar.update(1)
            pass
        return result


    def MongoDB(self):
        result=''
        try:
            conn = pymongo.MongoClient(self.rhost, self.MongoDBvuln, socketTimeoutMS=3000)
            default_dbname = conn.list_database_names()
            if default_dbname:
                result=self.rhost+" MongoDB Unauthorized"
        except Exception:
            pass
        finally:
            #self.bar.update(1)
            pass
        return result


    def Zookeeper(self):
        result=''
        try:
            socket.setdefaulttimeout(10)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.rhost, self.Zookeepervuln))
            s.send(bytes("envi\r\n", 'UTF-8'))
            results = s.recv(1024).decode()
            if "Environment" in results:
                result=self.rhost+" Zookeeper Unauthorized"
            s.close()
        except Exception:
            pass
        finally:
            #self.bar.update(1)
            pass
        return result



    def _verify(self):
        result = {}      
        functionname = [self.ActiveMQ, self.AtlassianCrowd, self.CouchDB, self.DockerAPI, self.Dubbo, self.Druid,
                    self.Elasticsearch, self.Ftp, self.HadoopYARN, self.JBoss, self.Jenkins, self.JupyterNotebook,
                    self.Kibana, self.KubernetesApiServer, self.ldap_anonymous, self.Weblogic, self.Solr, self.Springboot,
                    self.RabbitMQ, self.Zabbix, self.Redis, self.Rsync, self.NFS, self.Memcache, self.MongoDB, self.Zookeeper,
                    self.memcached
                    ]
        with ThreadPoolExecutor(10) as pool:
            obj_list=[]
            prt_list=[]
            for f in functionname:
                obj=pool.submit(f)
                obj_list.append(obj)

            
            for future in as_completed(obj_list):
                if future.result():
                    prt_list.append(future.result())


        if prt_list:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['VerifyInfo']['info'] = {}
            result['VerifyInfo']['info']['Severity']=self.severity
            result['VerifyInfo']['info']['Result']=' , '.join(prt_list)
            result['VerifyInfo']['info']['file_name'] = os.path.basename(__file__)

        if result:
            return self.parse_output(result)

    def _attack(self):

        return self._verify()

    def _shell(self):
        return self._verify()

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output


register_poc(DemoPOC)
