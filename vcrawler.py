import os
import pandas as pd
import numpy as np
import warnings

import time
import requests
import json


def load_files(file_list):
    import json
    features_list = []
    for filename in file_list:
        with open(filename,'rb') as f:
            features = extract_features(json.loads(f.read()))
            features_list.append(features)
    return features_list

def file_name(file_dir):   
    L=[]   
    for root, dirs, files in os.walk(file_dir):  
        for file in files:              
             L.append(os.path.join(root, file))  
    return L 


scaresdidr='scan_res/'
scanfir='scan/'
'''
data/bad/','data/good/目录分别恶意样本和正常

1）首先上传样本到杀毒网站扫描，排队进行扫描，
    返回每个文件的扫描简介（.scan），包括唯一scan_id，保存在'scan/bad/'和,'scan/good/目录中
2）等待一段时间，比如1天后
3）依据读.scan文件中scan_id，下载样本的杀毒报告，保存在'scan_res/bad/'和,'scan_res/good/目录中
  注意下载杀毒报告不能一次下载完，需要多运行几次，对比上传样本数量即可
  程序设置了已经下载的报告，不会再次下载
'''


ifscan=False #True表示上传样本杀毒网站扫描，False表示下载扫描结果

mykey= '56c44e07918cc73d7ec47682f219871cedb623f9a7a9ad6e3091075e582bbea1'

if ifscan:
#
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey':mykey}
    dirs=['data/bad/','data/good/']
   
    pos1=-1
    for dir in dirs:
        dataFiles=file_name(dir)
        pos1=dir.find('bad')     
        if   pos1>0:
            scanfir='scan/bad/'         
        else:
            scanfir='scan/good/'           

        for file in dataFiles:          

            files = {'file': (file, open(file, 'rb'))}

            response = requests.post(url, files=files, params=params)
           
            res=response.json()
            (filepath, filename) = os.path.split(file);
            dirw=scanfir+filename+'.scan'
            json.dump(res, open(dirw,'w'))
            time.sleep(1)
    
else:
#////////////////////
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    dirs=['scan/bad/','scan/good/']
    pos1=-1
    for dir in dirs:
        dataFiles=file_name(dir)
        pos1=dir.find('bad')     
        scanFiles=file_name(dir)

        if   pos1>0:
            scaresdidr='scan_res/bad/'
        else:
            scaresdidr='scan_res/good/'

        for file in scanFiles:
            (filepath, filename) = os.path.split(file)
            dirw=scaresdidr+filename.split('.')[0]+'.vtdata'
            if os.path.exists(dirw):
                continue

            with open(file,'rb') as f:
                data=json.loads(f.read())
                
                scan_id=data['scan_id']
           
                params = {'apikey': mykey, 'resource': scan_id,'allinfo':True}

                response_r = requests.get(url, params=params)
                if response_r.status_code==204:
                    time.sleep(5)
                    continue
                res_json=response_r.json()    
                
                json.dump(res_json, open(dirw,'w'))
                time.sleep(5)
