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

# Deafult platform is x86_64
PLATFORM="linux/x86_64"

# Special case for running on arm64 platforms
if [[ $ARCH == "arm" ]]
then
    PLATFORM="linux/arm64/v8"
    PLATFORM_PREFIX="arm64v8/"
fi

docker build --build-arg PLATFORM_PREFIX=$PLATFORM_PREFIX --platform $PLATFORM -t $DOCKNAME $DIRNAME

docker run --platform $PLATFORM -ti --rm -p $PORT:$PORT -v "$DIRNAME:/bundle" -u "`id -u`:`id -g`" $DOCKNAME /bins/entrypoint.sh -p$PORT $@
