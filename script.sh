#!/bin/bash

if [ ! -d logs ]; then
   mkdir logs
fi

cd logs

file=$(echo "$1" |  cut -d '/' -f 3)
echo "$file"
echo "A"
if [ ! -d $file ]; then
   mkdir $file
fi


python3 /home/k4lk1/Desktop/HAC/hac_site/crawl.py $1 >> $file/crawl_links.txt

cd $file
filename='crawl_links.txt'
echo "$filename"
while read line; do
    python3 /home/k4lk1/Desktop/HAC/hac_site/idor.py $line >> idor.txt
    python3 /home/k4lk1/Desktop/HAC/hac_site/xss.py $line >> xss.txt
    python3 /home/k4lk1/Desktop/HAC/hac_site/sqli.py $line >>sqli.txt
    python3 /home/k4lk1/Desktop/HAC/hac_site/lfi.py $line >> lfi.txt
    if [ $line == *"home"* ] || [ $line == *"login"* ]; then
        python3 /home/k4lk1/Desktop/HAC/hac_site/click.py $line >> click.txt
    fi
done < $filename




