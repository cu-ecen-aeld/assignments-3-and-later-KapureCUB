#!/bin/bash

#find /home/deka5322/aesd/assignment-1-KapureCUB/finder-app -type f -print0 | while read -d $'\0' file; do
#   echo "Processing $file"
#done

function help_log {
	echo "USAGE: ./finder.sh filesdir searchstr"
	echo "    filesdir  - path to search for string"
	echo "    searchstr - string to search for"
	
	echo "\n\nExample usage: ./finder.sh /home/work/dir foo"
}

