#!/usr/bin/env bash

gofilesStr=$(find ./ -name '*.go' |tr "\n" " ")

gofiles=($gofilesStr)

# sort it
IFS=$'\n' gofiles=($(sort <<<"${gofiles[*]}"))
unset IFS

printf '%-40s%-15s%-15s%-15s%-15s%-15s%-15s\n' "file" "brackets" "comments" "blanks" "not-counting" "counting" "full"

TOTAL_COUNT=0
for i in "${gofiles[@]}"
do
    if  [[ "$i" == *"bls_util.go" ]]; then
        continue
    fi
    BRACKETS=`cat "$i" | grep --extended-regexp "^\s*(\{|\}|\(|\))\s*$" | wc -l`
    COMMENTS=`cat "$i" | grep --extended-regexp "\s*//.+$" | wc -l`
    BLANKS=`cat "$i" | grep --extended-regexp "^$" | wc -l`
    FULL=`cat "$i" | wc -l`
    NOT_COUNTING=$(($BRACKETS + $COMMENTS + $BLANKS))
    COUNTING=$(($FULL - $NOT_COUNTING))
    TOTAL_COUNT=$(($TOTAL_COUNT + $COUNTING))
    printf '%-40s%-15s%-15s%-15s%-15s%-15s%-15s\n' "$i" "$BRACKETS" "$COMMENTS" "$BLANKS" "$NOT_COUNTING" "$COUNTING" "$FULL"
done

echo "total counting lines: $TOTAL_COUNT"
