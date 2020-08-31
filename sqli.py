#!/bin/python3

import requests
from bs4 import BeautifulSoup as bs
import sys
from urllib.parse import urljoin

printres = {}
sqli_url = []
sqli_method = []

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
        if r.status_code == 500 or "Internal Server Error" in r.text:
            sqli_url.append(r.url)
            sqli_method.append("GET")
            success_db.append(payload[0])
            return True
    sqli_url.append(r.url)
    sqli_method.append("GET")
    return False

def submit_form_sqli(form_details, url, value, cookie):
    #print("Value:",value)
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
        #print(data)
        if result.status_code == 500 or "Internal Server Error" in result.text:
            sqli_url.append(result.url)
            sqli_method.append("POST")
            return True
        else:
            sqli_url.append(result.url)
            sqli_method.append("POST")
            return False

    else:
        # GET request
        result = requests.get(target_url, params=data)
        #print(result.text)
        if result.status_code == 500 or "Internal Server Error" in result.text:
            sqli_url.append(result.url)
            sqli_method.append("GET")
            return True
        else:
            sqli_url.append(result.url)
            sqli_method.append("GET")
            return False


def scan_sqli(url):
    # get all the forms from the URL
    forms,inputs = get_all_forms_sqli(url)
    
    #print("\n[+] Running SQLi on ",url)
    payloads = [["conv('a',16,2)=conv('a',16,2)"                   ,"MYSQL"],
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
    """
    fh = open("auth_bypass.txt","r")
    for words in fh:
        words = words.split('\n')
        payloads.append(words)
    """
    # returning value
    is_vulnerable = False
    
    # iterate over all forms
    if len(forms) != 0:
        for form in forms:
            if is_vulnerable is False:
                form_details,cookie = get_form_details_sqli(form)
                for payload in payloads:
                    if submit_form_sqli(form_details, url, payload[0], cookie):
                        is_vulnerable = True
                        break
            else:
                break
    else:
        if db_info(url):
            is_vulnerable = True        
    
    if is_vulnerable is True:
        printres.update(SQLI= "Is Vulnerable")
        return printres
    else:
        printres.update(SQLI = "Not Vulnerable")
        return printres

if __name__ == "__main__":
    #url = input()
    url = str(sys.argv[1])
    printres=scan_sqli(url)
    if "Is Vulnerable" in printres['SQLI']:
        try:
            print(printres['SQLI'],sqli_method[0]+":"+sqli_url[0])
        except:
            print(printres['SQLI'],sqli_method[0]+":"+url)
    else:
        print(printres['SQLI'],sqli_method[0]+":"+url)
    
