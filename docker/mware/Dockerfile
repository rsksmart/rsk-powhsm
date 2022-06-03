FROM python:3.7.10-slim-stretch

WORKDIR /hsm2

RUN apt-get update && \
    apt-get install -y apt-utils vim && \
    apt-get install -y build-essential=12.3 && \
    apt-get install -y git

# Python package prerequisites
RUN apt-get install -y \
    libsecp256k1-dev=0.1~20161228-1 \
    python3-pkgconfig=1.2.2-1 \
    libusb-1.0-0-dev=2:1.0.21-1 \
    libudev-dev=232-25+deb9u12 \
    libffi-dev=3.2.1-6 #\
    libjpeg-dev=1:1.5.1-2+deb9u2

COPY requirements.txt /hsm2/requirements.txt
RUN pip install -r requirements.txt --require-hashes
RUN rm -f requirements.txt

# Hidapi wrapper with hid_exit support
RUN pip install git+https://github.com/rsksmart/cython-hidapi@0.10.1.post1

