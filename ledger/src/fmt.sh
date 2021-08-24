#! /usr/bin/env bash

#
# Format C code under ledger folder.
#
# This script assumes it's executed from the project's
# root, and that clang-format is installed.
#

find ./ -name "*.[ch]" |                            \
egrep -v "ui/.+[ch]$" |                             \
egrep -v "(bigdigits|bigdtypes|keccak256)\.[ch]$" | \
xargs clang-format --style=file -i

exit 0
