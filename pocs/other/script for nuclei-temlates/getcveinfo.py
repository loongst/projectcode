import os
import sys
import pathlib
from pathlib import *
import yaml
import pymysql
import json
input_path=r"nuclei"



def getfileinfo():
    result={}
    id=0
    nuclei=Path(input_path)
    for item in nuclei.rglob("*"):
        if item.is_file():
            if str(item).endswith("yaml"):
                print(item)
                id+=1
                result[id]={}
                filename=str(item).split("\\")[-1]

                if "CVE" in filename or "CNVD" in filename :
                    result[id]['cve']=filename.split(".")[0]
                else:
                    result[id]['cve']=''

                result[id]['file_name']=filename

                with Path.open(item,"r+",encoding="utf-8") as f:
                    content=f.read()
                    con=yaml.safe_load(content)
                    result[id]['poc_name']=con.get('info',{}).get('name')
                    result[id]['description']=con.get('info',{}).get('description')
        else:
            # print("this is folder")
            pass
    return result


def insert2mysql(result):
    # print(list(result.get(1,{}).values()).append(''))
    conn = pymysql.connect(
        host="localhost",
        port=3306,
        user="root",
        passwd="root",
        db="cve" 
        )
    #获取一个游标对象
    cursor=conn.cursor()
    #设置参数i，for语句循环
    for i in result:
        res=list(result.get(i).values())
        cve,file_name,poc_name,description=res[0],res[1],res[2],res[3]
        sql='''insert into poc_list values(null,%s,%s,%s,%s)'''
        print(cve,file_name,poc_name,description)
        cursor.execute(sql,(cve,file_name,poc_name,description))
        conn.commit()
    #关闭连接
    conn.close()
    cursor.close()

# res=getfileinfo()
# for i in res:
#     print(type(res.get(i)))
# print(len(res))


# print(len(l))

def main():
    # aa=getfileinfo()
    # with open('tmp.txt',"a+") as f:
    #     f.write(json.dumps(aa,ensure_ascii=True))
    insert2mysql(getfileinfo())

if __name__== "__main__" :
    main()