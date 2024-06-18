#!/bin/bash

CURDIR=$(dirname $0)
DESTDIR=$(realpath $CURDIR/dist/bin)
ROOTDIR=$(realpath $CURDIR/../../)

mkdir -p $DESTDIR

echo "Building TCPSigner..."

$ROOTDIR/firmware/build/build-tcpsigner > /dev/null 2>&1
cp $ROOTDIR/firmware/src/tcpsigner/tcpsigner $DESTDIR

echo "Building TCPManager..."

$ROOTDIR/middleware/build/manager-tcp > /dev/null 2>&1
cp $ROOTDIR/middleware/bin/manager-tcp.tgz $DESTDIR

echo "Done."
