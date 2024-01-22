#!/bin/bash
# Writer Script
# This script is used for writing a specified string to the provided file path
# Also creates the file if it does not exist 
# Author: Deepak Eknath Kapure

# global variable defines
FILE=""
STRING=""
GTG=0
DIRSTR=""

# help log function
function help_log {
        echo -e "\nUSAGE: ./writer.sh writefile writestr"
        echo "    writefile  - file to overwrite"
        echo "    writestr   - string to write"

        echo -e "\nExample usage: ./writer.sh /home/work/file.txt foo"
}

# check if arguments are valid
if [ -n "$1" ]
then
        if [ -n "$2" ]
        then
		FILE=$1
		STRING=$2
                if [ -f "$1" ]
                then
                    GTG=1
                else
		    # file does not exist
		    FILE=$1
		    DIRSTR=$(dirname $FILE)
		    mkdir -p ${DIRSTR} && touch ${FILE}
		    if [ $? -eq 0 ]
		    then
			    GTG=1
		    else
                        echo "Error 1: Unable to create file ${FILE}"
			help_log
                        exit 1
		    fi
                fi
        else
            echo "Error 1: writestr parameter not specified"
	    help_log
            exit 1
        fi
else
        echo "Error 1: writefile parameter not specified."
	help_log
        exit 1
fi

# overwrite the file with string data
if [ $GTG -eq 1 ]
then
	echo ${STRING} > ${FILE}
fi
