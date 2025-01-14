FROM python:3.13-slim-bookworm@sha256:23a81be7b258c8f516f7a60e80943cace4350deb8204cf107c7993e343610d47

WORKDIR /hsm2

RUN apt-get update && \
    apt-get install -y apt-utils vim procps && \
    apt-get install -y build-essential=12.9 && \
    apt-get install -y git && \
    apt-get install -y lcov

# Python package prerequisites
RUN apt-get install -y \
    libsecp256k1-dev=0.2.0-2 \
    libudev-dev=252.33-1~deb12u1 \
    libusb-1.0-0-dev=2:1.0.26-1 \
    libffi-dev=3.4.4-1 \
    libjpeg-dev=1:2.1.5-2

COPY requirements.txt /hsm2/requirements.txt
RUN pip install -r requirements.txt --require-hashes
RUN rm -f requirements.txt

# Hidapi wrapper with hid_exit support
RUN pip install --use-pep517 git+https://github.com/rsksmart/cython-hidapi@0.10.1.post2
