import os
import sys
import yaml
import logging
from os import walk
import coloredlogs
import re

## 配置 logger
logging.basicConfig()
logger = logging.getLogger(name='logger')

coloredlogs.install(logger=logger)
logger.propagate = False

## 配置 颜色
coloredFormatter = coloredlogs.ColoredFormatter(
    fmt='[%(name)s] %(asctime)s %(funcName)s %(lineno)-3d  %(message)s',
    level_styles=dict(
        debug=dict(color='white'),
        info=dict(color='blue'),
        warning=dict(color='yellow', bright=True),
        error=dict(color='red', bold=True, bright=True),
        critical=dict(color='black', bold=True),
    ),
    # field_styles=dict(
    #     name=dict(color='white'),
    #     asctime=dict(color='white'),
    #     funcName=dict(color='green'),
    #     lineno=dict(color='white'),
    # )
)

## 配置 StreamHandler
ch = logging.StreamHandler(stream=sys.stdout)
ch.setFormatter(fmt=coloredFormatter)
logger.addHandler(hdlr=ch)
logger.setLevel(level=logging.DEBUG)


class Renamefile:
    FILE_PATH=r"C:\Users\loong\Desktop\nuclei-templates-9.5.0\network\cves"

    #modify yaml file
    def get_modify_fileinfo(self,file):
        file_name=os.path.basename(file)
        with open(file,"r+",encoding='utf-8') as f:
            data=yaml.safe_load(f)
            logger.warning(file)
            print(data)
            a=data['id']
            b=data['info']['name']
            if "CVE-" in file_name or "CNVD-" in file_name:
            # logger.warning(data['info']['tags'])
                a="("+a+")"
                return "-".join([b,a])+".yaml"
            else:
                return b+".yaml"

    def file_rename(self,file,root,newname):
        newname=re.sub(r'[\/:*?"<>|=]',"", newname)
        newname=newname.replace(" ","-")
        newname=re.sub(r"-{2,}",r"-", newname)
        if newname.startswith("Detect-"):
            newname=newname.replace("Detect-","")
            newname=newname.replace(".yaml","")
            newname=newname+"-detect.yaml"
        
        newname=os.path.join(root,newname)
        newname = "\\".join(newname.split("\\"))
        try:
            if not os.path.exists(newname):
                os.rename(file,newname)
        except Exception as e:
            logger.error(e)
        pass


    def get_filename_list(self):

        for root,dirs,files in os.walk(self.FILE_PATH):
            # logger.info(len(files))
            for file in files:
                #获取文件所属目录
                # print(root)
                # logger.info(root)
                # #获取文件路径
                # # print(os.path.join(root,file))
                # logger.info(os.path.join(root,file))
                if( not file.startswith(".") and (file.endswith("yaml") or file.endswith("yml"))):
                    file_newname=self.get_modify_fileinfo(os.path.join(root,file))
                    self.file_rename(os.path.join(root,file),root,file_newname)
                else:
                    # logger.info(file)
                    pass
    
def main():
    e=Renamefile()
    e.get_filename_list()

if  __name__=="__main__":
    main()

