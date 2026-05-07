#!/bin/bash

KEY_ID="e4548bc2-cfa6-40f1-b9e9-960779369798"

if [ -z "$1" ]; then
    aws kms get-key-policy --key-id $KEY_ID | jq '.Policy' | xargs -0 echo -e
else
    if [ ! -f "$1" ]; then
        echo "Error: File '$1' not found!"
        exit 1
    fi
    POLICY=$(cat $1 | jq -c)
    aws kms put-key-policy --key-id $KEY_ID --policy-name default --policy "$POLICY"
fi
