#!/bin/bash

CURDIR=$(dirname $0)
DESTDIR=$(realpath $CURDIR/dist/bin)
ROOTDIR=$(realpath $CURDIR/../../)

mkdir -p $DESTDIR

echo "Building TCPSigner..."

$ROOTDIR/ledger/build/build-tcpsigner > /dev/null 2>&1
cp $ROOTDIR/ledger/src/tcpsigner/tcpsigner $DESTDIR

echo "Building TCPManager..."

$ROOTDIR/middleware/build/manager-tcp > /dev/null 2>&1
cp $ROOTDIR/middleware/bin/manager-tcp.tgz $DESTDIR

echo "Done."
