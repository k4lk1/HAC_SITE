import re
from pathlib import Path
from vuln_scanner.models import site
def read_status_lfi(self,url,*args, **kwargs):
    data_folder = Path("/home/k4lk1/Desktop/HAC/hac_site/logs/")
    file_to_open = data_folder/url/"lfi.txt"
    print(url)
    f = open(file_to_open, 'r')
    file_content = f.read()
    f.close()
    context = {'file_content': file_content}
    return context

def read_status_idor(self,url,*args, **kwargs):
    data_folder = Path("/home/k4lk1/Desktop/HAC/hac_site/logs/")
    file_to_open = data_folder/url/"idor.txt"
    print(url)
    f = open(file_to_open, 'r')
    file_content = f.read()
    f.close()
    context = {'file_content': file_content}
    return context

def read_status_sqli(self,url,*args, **kwargs):
    data_folder = Path("/home/k4lk1/Desktop/HAC/hac_site/logs/")
    file_to_open = data_folder/url/"sqli.txt"
    print(url)
    f = open(file_to_open, 'r')
    file_content = f.read()
    f.close()
    context = {'file_content': file_content}
    return context
def read_status_xss(self,url,*args, **kwargs):
    data_folder = Path("/home/k4lk1/Desktop/HAC/hac_site/logs/")
    file_to_open = data_folder/url/"xss.txt"
    print(url)
    f = open(file_to_open, 'r')
    file_content = f.read()
    f.close()
    context = {'file_content': file_content}
    return context