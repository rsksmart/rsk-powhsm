FROM debian:buster-slim

WORKDIR /hsm2

RUN apt-get update && \
    apt-get install -y apt-utils vim

# Python 3.7 and pip
RUN apt-get install -y python3.7=3.7.3-2+deb10u2 python3.7-dev=3.7.3-2+deb10u2
RUN apt-get install -y python3-pip=18.1-5
RUN ln -s /usr/bin/python3 /usr/bin/python
RUN ln -s /usr/bin/pip3 /usr/bin/pip

# Python package prerequisites
RUN apt-get install -y \
    libsecp256k1-dev=0.1~20170810-2 \
    python3-pkgconfig=1.4.0-1 \
    libusb-1.0-0-dev=2:1.0.22-2 \
    libudev-dev=241-7~deb10u5 \
    libffi-dev=3.2.1-9 \
    libjpeg-dev=1:1.5.2-2+deb10u1

COPY requirements.txt /hsm2/requirements.txt
RUN pip install -r requirements.txt --require-hashes
RUN rm -f requirements.txt
