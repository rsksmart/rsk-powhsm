FROM debian:bullseye-slim

WORKDIR /hsm2

RUN apt-get update && \
    apt-get install -y apt-utils

# Python 3.8 and pip
RUN apt-get install -y python3.8=3.8.6-1 python3.8-dev=3.8.6-1
RUN apt-get install -y python3-pip=20.1.1-2
RUN ln -s /usr/bin/python3 /usr/bin/python

# Python package prerequisites
RUN apt-get install -y \
    libsecp256k1-dev=0.1~20170810-2 \
    python3-pkgconfig=1.5.1-3 \
    libusb-1.0-0-dev=2:1.0.23-3 \
    libudev-dev=247.1-3 \
    libffi-dev=3.3-5 \
    libjpeg-dev=1:2.0.5-1.1

COPY requirements.txt /hsm2/requirements.txt
RUN pip install -r requirements.txt --require-hashes
RUN rm -f requirements.txt
