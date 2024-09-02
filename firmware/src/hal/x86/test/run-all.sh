#!/bin/bash
ROOTDIR=$(dirname $0)/../../../../..
TESTDIR=$(realpath $(dirname $0) --relative-to $ROOTDIR)
TESTDIRS="bip32 hmac_sha256"
TESTDIRS=${1:-"$TESTDIRS"}

for d in $TESTDIRS; do
    echo "******************************"
    echo "Testing $d..."
    echo "******************************"
    $ROOTDIR/docker/mware/do-notty-nousb /hsm2/$TESTDIR/$d "make clean test" || exit $?
done
