#!usr/bin/env python3
from bs4 import BeautifulSoup as bs
import requests
import requests.exceptions
from urllib.parse import urlsplit
from urllib.request import urlopen
from urllib.parse import urljoin
import requests.exceptions
import urllib.request as urllib
from urllib.parse import urlparse
from urllib.request import HTTPError
from requests.exceptions import MissingSchema
from collections import deque
import re ,ssl
import random
import os
from multiprocessing import Process
import subprocess
#import ddos_detect #Uncomment this for using ddos_detect script
import sys

count_idor = 0
count_xss = 0
count_sqli = 0
count_lfi = 0
count_click = 0

params_links = []
printres = {}
url = "http://testing1.pentest-tools.com/dvwa"  #Change the URL 

def limit_crawler(domain, ofile, limit, mute):
    try:
        # a queue of urls to be crawled
        new_urls = deque([domain])
        # a set of urls that we have already crawled
        processed_urls = set()
        # a set of domains inside the target website
        limit_urls = set()
        # a set of domains outside the target website
        limit_urls = set()
        # a set of broken urls
        broken_urls = set()

        # process urls one by one until we exhaust the queue
        while len(new_urls):

            # move next url from the queue to the set of processed urls
            url = new_urls.popleft()
            processed_urls.add(url)
            # get url's content
            #print("Processing %s" % url)
            try:
                response = requests.get(url)
                #print(url)
            except (requests.exceptions.MissingSchema, requests.exceptions.ConnectionError, requests.exceptions.InvalidURL, requests.exceptions.InvalidSchema):
                # add broken urls to it's own set, then continue
                broken_urls.add(url)
                continue

            # extract base url to resolve relative links
            parts = urlsplit(url)
            base = "{0.netloc}".format(parts)
            strip_base = base.replace("www.", "")
            base_url = "{0.scheme}://{0.netloc}".format(parts)
            path = url[:url.rfind('/')+1] if '/' in parts.path else url

            # create a beutiful soup for the html document
            soup = bs(response.text, "lxml")

            for link in soup.find_all('a'):
                # extract link url from the anchor
                anchor = link.attrs["href"] if "href" in link.attrs else ''
                if "www" not in anchor:
                    if './' in anchor:
                        a = anchor.find('./')
                        anchor = anchor[a+2:]
                    ofile.append(domain+anchor)
                    #print(anchor)

                if limit in anchor:
                    limit_urls.add(anchor)
                else:
                    pass

            for i in limit_urls:
                if not i in new_urls and not i in processed_urls:
                    new_urls.append(i)

        return ofile
    
    except KeyboardInterrupt:
        sys.exit()

if __name__ == "__main__":
    domain = url
    ofile= list()
    mute=0
    limit=domain
    limit_crawler(domain,ofile,limit,mute)
    #print(ofile)
    for url in ofile:
        burl = bytes(url, 'utf-8') #encoding the url in byte form to be passed as input for subprocess
        result = subprocess.run(["python3", "idor.py"], input=burl, stdout=subprocess.PIPE)
        res = result.stdout.splitlines()
        try:
            res = res[0].decode('utf-8')
        except:
            continue
        if url in res:
            params_links.append(res)
        if "Is Vulnerable" in res:
            count_idor += 1
        printres.update(IDOR = res)
        print(printres)
    printres = {}
    for url in params_links+ofile:
        burl = bytes(url, 'utf-8')
        #XSS
        result = subprocess.run(["python3", "xss.py"], input=burl, stdout=subprocess.PIPE)
        res = result.stdout.splitlines()
        try:
            res = res[0].decode('utf-8')
            printres.update(XSS = res)
            if "Is Vulnerable" in res:
                count_xss += 1
        except:
            pass
        #print(res)
        
        #SQLI
        result = subprocess.run(["python3", "sqli.py"], input=burl, stdout=subprocess.PIPE)
        res = result.stdout.splitlines()
        #print("SQLI:",res)
        try:
            res = res[0].decode('utf-8')
            printres.update(SQLI = res)
            if "Is Vulnerable" in res:
                count_sqli += 1
        except:
            pass

        #LFI
        result = subprocess.run(["python3", "lfi.py"], input=burl, stdout=subprocess.PIPE)
        res = result.stdout.splitlines()
        #print("LFI:",res)
        try:
            res = res[0].decode('utf-8')
            printres.update(LFI = res)
            if "Is Vulnerable" in res:
                count_lfi += 1
        except:
            pass

        #CLICK
        if "home" in url or "login" in url: #For ClickJacking
            result = subprocess.run(["python3", "click.py"], input=burl, stdout=subprocess.PIPE)
            res = result.stdout.splitlines()
            #print("CLICK:",res)
            try:
                res = res[0].decode('utf-8')
                printres.update(CLICK = res)
                if "Is Vulnerable" in res:
                    count_click += 1
            except:
                pass

        print(printres)
    #ddos_detect.main() # Needs certain modules to be downloaded, run: pip3 install -r ddos_requirements.txt
