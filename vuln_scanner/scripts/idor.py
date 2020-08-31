#!/bin/python3
import ssl, re
from urllib.request import urlopen
from bs4 import BeautifulSoup as bs
import random
import requests
import sys

printres = {} #Stores if a particular vulnerability exits or not in a given link. Note the value gets changed for every link, it cannot be appeneded
param_vulns = [] #List that stores all links which has a parameter at its end eg: index.php?a=2
idor_vuln_links = list()
#url = "https://juice-shop.herokuapp.com/#/"


# This Function changes the param value by taking a random from 1 to 20, and checks for any redirections or changes in response text
def confirm_idor(url):  
    response_text = []  #List to store response text for different values sent as a requests
    for i in range(20):
        val = random.randint(1,20)
        f = url.find('=')
        furl = url[:f+1]+str(val)
        r =  requests.get(furl)
        if i == 0:
            response_text.append(r.text)
            if r.status_code >= 300 and r.status_code <= 310:
                return True
        else:
            if r.status_code >= 300 and r.status_code <= 310 or r.text not in response_text : #If condition is met Possibility of IDOR
                response_text.append(r.text)
                return True
            elif i == 20:  #To run for 20 iterations
                return False
            else:
                continue

def scan_idor(url):
    #for url in directories+php_files:
    params = []
    #print("\n[+] Running Tests for IDOR on",url)
    link=''
    #Handles the SSl certificate errors
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    html = urlopen(url, context=ctx).read()
    soup = bs(html, "html.parser")
    tags = soup('a')
    general_links = list()
        
    for tag in tags:
        link1 = tag.get('href',None)
        link=str(link1)
        #print(link)
        zzz=".+\?.+"
        # Checks for possible links
        if re.findall(zzz, link):
            general_links.append(link)
            # Checks for specific that are prone to bruteforcing 
            if re.findall('\?.+=[0-9]+.',link):
                idor_vuln_links.append(link)
        

    #                # Checks if and only the parameter has numeric value and only had occured once 
    #                if re.search('([0-9]+)', url): #  <---------------- this part needs work cant get the regex to extract 
    #                    idor_vuln_links[link] = is_brute_forcable(link)
    #                else :
    #                    # Havent designed to check for multiple parameters
    #                    idor_vuln_links[link] = 'Dont know'

    if len(general_links) != 0:
        #Prints out all the links 
        #print(*idor_vuln_links, sep='\n')
        for vulns in idor_vuln_links:
            a = vulns.find('?')
            b = vulns.find('=')
            if params == [] or vulns[a+1:b] not in params:
                params.append(vulns[a+1:b])
                if "www" not in vulns:
                    x = vulns.find('=')
                    vulns = vulns[:x+1]
                    if "./" in vulns:
                        k = vulns.find('./')
                        #print(vulns[k+2:])
                        if confirm_idor(url+vulns[k+2:]):
                            if url+vulns[k+2:] not  in idor_vuln_links:
                                idor_vuln_links.append(url+vulns[k+2:])
                            if url+vulns[k+2:] not in param_vulns:
                                param_vulns.append(url+vulns[k+2:])
                            printres.update(IDOR = "Is Vulnerable")
                            break
                        else:
                            printres.update(IDOR = "Not Vulnerable")
                            if url+vulns[k+2:] not in param_vulns:
                                param_vulns.append(url+vulns[k+2:])
                            break

                    else:
                        #print(vulns)
                        if confirm_idor(url+vulns):
                            if url+vulns not in idor_vuln_links:
                                idor_vuln_links.append(url+vulns)
                            if url+vulns not in param_vulns:
                                param_vulns.append(url+vulns)
                            printres.update(IDOR = "Is Vulnerable")
                            break
                        else:
                            printres.update(IDOR = "Not Vulnerable")
                            if url+vulns not in param_vulns:
                                param_vulns.append(url+vulns)
                            break

            else:
                continue  
        #print(*general_links, sep='\n')
        for gens in general_links:
            a = gens.find('?')
            b = gens.find('=')
            if params == [] or gens[a+1:b] not in params:
                params.append(gens[a+1:b])
                if "www" not in gens:
                    x = gens.find('=')
                    gens = gens[:x+1]
                    if "./" in gens:
                        k = gens.find('./')
                        #print(gens[k+2:])
                        if url+gens[k+2:] not in param_vulns:
                            param_vulns.append(url+gens[k+2:])
                    else: 
                        #print(gens)
                        if url+gens not in param_vulns:
                            param_vulns.append(url+gens)
            else:
                continue
        printres.update(IDOR = "Not Vulnerable")
        #printres.update(IDOR = "Is Vulnerable")
        #print("[!] Vulnerable To IDOR")
        #print("[*] Saved in links.txt")
    else:
        printres.update(IDOR = "Not Vulnerable")


if __name__=="__main__":
    #url = input()
    url = sys.argv[1]
    scan_idor(url)
    if "Is Vulnerable" in printres['IDOR']:
        print(printres['IDOR'],"GET:"+idor_vuln_links[0])
    else:
        print(printres['IDOR'],"GET:"+url)

