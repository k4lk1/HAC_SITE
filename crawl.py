from bs4 import BeautifulSoup as bs

import requests

import requests.exceptions

from urllib.parse import urlsplit

from collections import deque

import re

import sys

import os





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
            try:
                response = requests.get(url)
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



if __name__=='__main__':

    domain=str(sys.argv[1])

    ofile=list()

    mute=0

    limit=domain

    links = limit_crawler(domain,ofile,limit,mute)
    #print(links)

    for link in links:
        print(link)

    #idor(links)
