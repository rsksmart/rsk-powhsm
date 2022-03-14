#!/bin/bash

DIRNAME=$(realpath $(dirname $0))

DOCKNAME=tcpsigner-bundle

# ==========================================================
# ==========================================================
# Change this to change the default port on which the 
# TCPSigner bundle runs
PORT=9999

while getopts ":p:" opt; do
    case "$opt" in
    p)
        PORT=$OPTARG 
        ;;
    esac
done
# ==========================================================
# ==========================================================

docker build --platform linux/x86_64 -t $DOCKNAME $DIRNAME

docker run --platform linux/x86_64 -ti --rm -p $PORT:$PORT -v "$DIRNAME:/bundle" -u "`id -u`:`id -g`" $DOCKNAME /bins/entrypoint.sh -p$PORT $@
