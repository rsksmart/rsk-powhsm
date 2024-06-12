#!/bin/bash
BASEDIR=$(dirname $0)
TESTDIRS="attestation bootloader onboard pin signer_authorization ui_comm ui_heartbeat unlock ux_handlers"
TESTDIRS=${1:-"$TESTDIRS"}

for d in $TESTDIRS; do
    echo "******************************"
    echo "Testing $d..."
    echo "******************************"
    cd "$BASEDIR/$d"
    make clean test || exit $?
    cd - > /dev/null
done
