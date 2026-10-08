#!/bin/bash

set -e

pushd $(dirname "$0") > /dev/null

python -m pip install --timeout=60 -r requirements.txt --require-hashes
# Hidapi wrapper with hid_exit support (same as docker/mware/Dockerfile)
# https://github.com/rsksmart/cython-hidapi/releases/tag/0.10.1.post2 pinned by hash
python -m pip install --timeout=60 --use-pep517 git+https://github.com/rsksmart/cython-hidapi@56d87e287e4da8fc379e3b96573f5ac93e02e613

popd > /dev/null
