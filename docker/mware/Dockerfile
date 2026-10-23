FROM python:3.12-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70

ARG SNAPSHOT_DATE=20261023T000000Z
ENV PIP_VERSION=26.2.2
ENV PIP_HASH=fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70
ARG PIP_TIMEOUT=60

WORKDIR /hsm2

RUN rm -f /etc/apt/sources.list.d/debian.sources && \
    echo "deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/${SNAPSHOT_DATE}/ bookworm main" > /etc/apt/sources.list && \
    echo "deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/${SNAPSHOT_DATE}/ bookworm-updates main" >> /etc/apt/sources.list && \
    echo "deb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/${SNAPSHOT_DATE}/ bookworm-security main" >> /etc/apt/sources.list

RUN apt-get update && \
    apt-get install -y apt-utils vim procps && \
    apt-get install -y ca-certificates=20250419~deb12u2 && \
    apt-get install -y build-essential=12.9 && \
    apt-get install -y git && \
    apt-get install -y lcov && \
    apt-get install -y libmbedtls-dev=2.28.3-1

# Python package prerequisites
RUN apt-get install -y \
    libsecp256k1-dev=0.2.0-2 \
    libudev1=252.39-1~deb12u2 \
    libudev-dev=252.39-1~deb12u2 \
    libusb-1.0-0-dev=2:1.0.26-1 \
    libffi-dev=3.4.4-1 \
    libjpeg-dev=1:2.1.5-2

RUN echo "pip==${PIP_VERSION} --hash=sha256:${PIP_HASH}" > /tmp/pip-req.txt && \
    pip install --timeout=${PIP_TIMEOUT} --require-hashes -r /tmp/pip-req.txt && \
    rm -f /tmp/pip-req.txt

COPY requirements.txt /hsm2/requirements.txt
RUN pip install --timeout=${PIP_TIMEOUT} -r requirements.txt --require-hashes
RUN rm -f requirements.txt

# Hidapi wrapper with hid_exit support
# https://github.com/rsksmart/cython-hidapi/releases/tag/0.10.1.post2 pinned by hash
RUN pip install --timeout=${PIP_TIMEOUT} --use-pep517 git+https://github.com/rsksmart/cython-hidapi@56d87e287e4da8fc379e3b96573f5ac93e02e613
