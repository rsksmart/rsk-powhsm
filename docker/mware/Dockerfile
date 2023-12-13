FROM python:3.7.16-slim-bullseye

WORKDIR /hsm2

RUN apt-get update && \
    apt-get install -y apt-utils vim && \
    apt-get install -y build-essential=12.9 && \
    apt-get install -y git && \
    apt-get install -y lcov

# Python package prerequisites
RUN apt-get install -y \
    libsecp256k1-dev=0.1~20210108-1 \
    python3-pkgconfig=1.5.1-3 \
    libusb-1.0-0-dev=2:1.0.24-3 \
    libudev-dev=247.3-7+deb11u4 \
    libffi-dev=3.3-6 #\
    libjpeg-dev=1:2.0.6-4

COPY requirements-pre.txt /hsm2/requirements-pre.txt
RUN pip install -r requirements-pre.txt --require-hashes
RUN rm -f requirements-pre.txt

COPY requirements.txt /hsm2/requirements.txt
RUN pip install -r requirements.txt --require-hashes
RUN rm -f requirements.txt

# Hidapi wrapper with hid_exit support
RUN pip install git+https://github.com/rsksmart/cython-hidapi@0.10.1.post1

