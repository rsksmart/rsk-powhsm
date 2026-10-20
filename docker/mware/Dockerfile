FROM python:3.12-slim-bookworm@sha256:10f3aaab98db50cba827d3b33a91f39dc9ec2d02ca9b85cbc5008220d07b17f3

ARG PIP_TIMEOUT=60
ARG SNAPSHOT_DATE=20260415T000000Z

### Pinned digests and commits for downloaded dependencies ###

# Hidapi wrapper with hid_exit support (https://github.com/rsksmart/cython-hidapi)
# Commit is tag 0.10.1.post2 (https://github.com/rsksmart/cython-hidapi/releases/tag/0.10.1.post2)
ENV HIDAPI_COMMIT=56d87e287e4da8fc379e3b96573f5ac93e02e613

WORKDIR /hsm2

RUN rm -f /etc/apt/sources.list.d/debian.sources && \
    echo "deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/${SNAPSHOT_DATE}/ bookworm main" > /etc/apt/sources.list && \
    echo "deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/${SNAPSHOT_DATE}/ bookworm-updates main" >> /etc/apt/sources.list && \
    echo "deb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/${SNAPSHOT_DATE}/ bookworm-security main" >> /etc/apt/sources.list

RUN apt-get update && \
    apt-get install -y apt-utils vim procps && \
    apt-get install -y build-essential=12.9 && \
    apt-get install -y git && \
    apt-get install -y lcov && \
    apt-get install -y libmbedtls-dev=2.28.3-1

# Python package prerequisites
RUN apt-get install -y \
    libsecp256k1-dev=0.2.0-2 \
    libudev1=252.39-1~deb12u1 \
    libudev-dev=252.39-1~deb12u1 \
    libusb-1.0-0-dev=2:1.0.26-1 \
    libffi-dev=3.4.4-1 \
    libjpeg-dev=1:2.1.5-2

COPY requirements.txt /hsm2/requirements.txt
RUN pip install --timeout=${PIP_TIMEOUT} -r requirements.txt --require-hashes
RUN rm -f requirements.txt

# Hidapi wrapper with hid_exit support
# Build dependencies (setuptools, wheel, Cython) come from the hash-pinned requirements above
RUN pip install --timeout=${PIP_TIMEOUT} --use-pep517 --no-build-isolation --no-deps git+https://github.com/rsksmart/cython-hidapi@$HIDAPI_COMMIT
