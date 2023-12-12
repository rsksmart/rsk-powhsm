#!/bin/bash

N=$(echo $1 | sed -e "s/\..\+\$//g")

if [[ $N -gt 80 ]]; then
    echo "green"
elif [[ $N -gt 60 ]]; then
    echo "orange"
else
    echo "red"
fi

