#!/bin/bash
BASEDIR=$(dirname $0)
TESTDIRS="btcscript btctx difficulty srlp svarint trie"
TESTDIRS=${1:-"$TESTDIRS"}

for d in $TESTDIRS; do
    echo "******************************"
    echo "Testing $d..."
    echo "******************************"
    cd "$BASEDIR/$d"
    make clean test || exit $?
    cd - > /dev/null
done
