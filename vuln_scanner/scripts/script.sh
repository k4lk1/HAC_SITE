#!/bin/bash

<<<<<<< HEAD
if [ ! -d $url ]; then
   mkdir $url
fi

python3 crawl.py $url > txt/crawl_links.txt
=======
if [ ! -d txt ]; then
   mkdir txt
fi

python3 crawl.py $1 > txt/crawl_links.txt
>>>>>>> 8f084ba... Updated!

filename='txt/crawl_links.txt'
while read line; do
    python3 idor.py $line >> txt/idor_links.txt
    python3 xss.py $line >> txt/xss.txt
    python3 sqli.py $line >> txt/sqli.txt
    python3 lfi.py $line >> txt/lfi.txt
    if [ $line == *"home"* ] || [ $line == *"login"* ]; then
        python3 click.py $line >> txt/click.txt
    fi
done < $filename

<<<<<<< HEAD
=======
#python3 ddos_detect.py


>>>>>>> 8f084ba... Updated!
