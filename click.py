import requests
import sys
printres={}
click_url = []

def scan_click(url):
    #url=input("please enter the url")
    zz='<Response [406]>'
    s=requests.get(url)
    #print(s)
    if s.status_code != 200:
        printres.update(CLICK = 'Invalid Url')
        return printres
        #sys.exit(1)
        
    frm='iframe' 
    xfrm='Content-Security-Policy'
    xfrm2='X-Frame-Options'
    s=requests.session()
    r=s.get(url)
    r1=r.headers
    #print(r1)
    if xfrm in r1 or xfrm2 in r1:
        printres.update(CLICK = 'Not Vulnerable')
        return printres

    elif frm in r:
        click_url.append(r.url)
        printres.update(CLICK = 'Is Vulnerable')
        return printres

    else:
        printres.update(CLICK = 'Not Vulnerable')
        return printres

if __name__=="__main__":
    #url = input()
    url = str(sys.argv[1])
    printres = scan_click(url)
    if 'Is Vulnerable' in printres['CLICK']:
        print(printres['CLICK'],"GET:"+click_url[0])
    else:
        print(printres['CLICK'],"GET:"+url)
