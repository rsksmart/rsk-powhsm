#!/bin/bash

if [[ $1 == "exec" ]]; then
    BASEDIR=$(realpath $(dirname $0))
    TESTDIRS="upgrade system keyvalue_store"
    for d in $TESTDIRS; do
        echo "******************************"
        echo "Testing $d..."
        echo "******************************"
        cd "$BASEDIR/$d"
        make clean test || exit $?
        cd - > /dev/null
    done
    exit 0
else
    # Script directory
    REPOROOT=$(realpath $(dirname $0)/../../../../)
    SCRIPT=$(realpath $0 --relative-to=$REPOROOT)

    $REPOROOT/docker/mware/do-notty-nousb /hsm2 "./$SCRIPT exec"
fi
