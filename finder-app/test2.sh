#!/bin/bash

DIR=$1
STRING=$2
MATCHCNT=0
FILECNT=0

while IFS= read -r -d $'\0' FILE
do
    echo "Processing $FILE"
    grep -c "${STRING}" "${FILE}"
    let "FILECNT=FILECNT+1"
    echo "file count is $FILECNT"
    cmd=$(grep -c "${STRING}" "${FILE}")
    MATCHCNT=$((MATCHCNT+cmd))
done < <(find "${DIR}" -type f -print0)

echo "The number of files are $FILECNT and the number of matching lines are $MATCHCNT"

