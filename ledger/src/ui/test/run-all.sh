#!/bin/bash
BASEDIR=$(dirname $0)
TESTDIRS="attestation signer_authorization communication onboard pin unlock bootloader ux_handlers ui_heartbeat"
TESTDIRS=${1:-"$TESTDIRS"}

for d in $TESTDIRS; do
    echo "******************************"
    echo "Testing $d..."
    echo "******************************"
    cd "$BASEDIR/$d"
    make clean test || exit $?
    cd - > /dev/null
done
