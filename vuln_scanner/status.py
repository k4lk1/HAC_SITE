import re
from pathlib import Path
from vuln_scanner.models import site
#file_to_open = data_folder/domain/"sqli.txt"

#/home/k4lk1/Desktop/HAC/hac_site/logs/www.faceboook.com/

def read_sqli(self,url,*args, **kwargs):
    data_folder = Path("/home/k4lk1/Desktop/HAC/hac_site/logs/")
    file_to_open = data_folder/url/"sqli.txt"
    print(url)
    f = open(file_to_open,'r')
    file_content=f.readlines()
    f.close()
    status='Safe'
    print(status)
    for line in file_content:
       
        if re.search("Is Vulnerable", line,re.M|re.I):
            status='Vulnerable'
    print(status)
    return status
def read_xss(self,url,*args, **kwargs):
    data_folder = Path("/home/k4lk1/Desktop/HAC/hac_site/logs/")
    file_to_open = data_folder/url/"xss.txt"
    print(url)
    f = open(file_to_open,'r')
    file_content=f.readlines()
    f.close()
    status='Safe'
    print(status)
    for line in file_content:
       
        if re.search("Is Vulnerable", line,re.M|re.I):
            status='Vulnerable'
    print(status)
    return status

def read_idor(rself,url,*args, **kwargs):
    data_folder = Path("/home/k4lk1/Desktop/HAC/hac_site/logs/")
    file_to_open = data_folder/url/"idor.txt"
    print(url)
    f = open(file_to_open,'r')
    file_content=f.readlines()
    f.close()
    status='Safe'
    print(status)
    for line in file_content:
       
        if re.search("Is Vulnerable", line,re.M|re.I):
            status='Vulnerable'
    print(status)
    return status

def read_lfi(self,url,*args, **kwargs):
    data_folder = Path("/home/k4lk1/Desktop/HAC/hac_site/logs/")
    file_to_open = data_folder/url/"lfi.txt"
    print(url)
    f = open(file_to_open,'r')
    file_content=f.readlines()
    f.close()
    status='Safe'
    print(status)
    for line in file_content:
       
        if re.search("Is Vulnerable", line,re.M|re.I):
            status='Vulnerable'
    print(status)
    return status