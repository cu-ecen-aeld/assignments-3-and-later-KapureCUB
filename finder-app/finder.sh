#!/bin/sh
# Finder Script
# This script is used for searching a string pattern in all the files provided by the filesdir argument
# Also searches in the subdirectory files for the existence of given substring
# Author: Deepak Eknath Kapure

# global variables
DIR=""
STRING=""
MATCHCNT=0
FILECNT=0
GTG=0

# help log function
help_log() {
        printf "\nUSAGE: ./finder.sh filesdir searchstr\n"
        printf "    filesdir  - path to search for string\n"
        printf "    searchstr - string to search for\n"

        printf "\nExample usage: ./finder.sh /home/work/dir foo\n"
}

# check if the arguments are correct
if [ -n "$1" ]
then 
	if [ -n "$2" ]
        then
		if [ -d "$1" ]
                then
		    # valid path
                    DIR=$1
                    STRING=$2
                    GTG=1
                else
                    printf "Error 1: filesdir does not represent a directory on the file system"
		    help_log
                    exit 1
                fi
	else
            printf "Error 1: searchstr parameter not specified"
	    help_log
            exit 1
        fi
else
	printf "Error 1: filesdir parameter not specified."
        help_log
	exit 1
fi

# search for string in all the files
if [ $GTG -eq 1 ]
then
    # recurssively find the files in subdirectories.
    # preserving the file name using -print0 
    # also using process substitution instead of pipeline (|) to 
    # preserve the FILECNT and MATCHCNT
    cd $DIR
    FILECNT=$(ls -1 $DIR | wc -l)
    MATCHCNT=$(grep -r $STRING $DIR | wc -l)
    printf "The number of files are $FILECNT and the number of matching lines are $MATCHCNT\n"
fi
