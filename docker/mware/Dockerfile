FROM python:3.12-slim-bookworm@sha256:10f3aaab98db50cba827d3b33a91f39dc9ec2d02ca9b85cbc5008220d07b17f3

ARG PIP_TIMEOUT=60

WORKDIR /hsm2

RUN apt-get update && \
    apt-get install -y apt-utils vim procps && \
    apt-get install -y build-essential=12.9 && \
    apt-get install -y git && \
    apt-get install -y lcov

# Python package prerequisites
RUN apt-get install -y \
    libsecp256k1-dev=0.2.0-2 \
    libudev-dev=252.36-1~deb12u1 \
    libusb-1.0-0-dev=2:1.0.26-1 \
    libffi-dev=3.4.4-1 \
    libjpeg-dev=1:2.1.5-2

COPY requirements.txt /hsm2/requirements.txt
RUN pip install --timeout=${PIP_TIMEOUT} -r requirements.txt --require-hashes
RUN rm -f requirements.txt

# Hidapi wrapper with hid_exit support
# https://github.com/rsksmart/cython-hidapi/releases/tag/0.10.1.post2 pinned by hash
RUN pip install --timeout=${PIP_TIMEOUT} --use-pep517 git+https://github.com/rsksmart/cython-hidapi@56d87e287e4da8fc379e3b96573f5ac93e02e613
