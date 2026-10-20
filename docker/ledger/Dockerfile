FROM ubuntu:20.04@sha256:8feb4d8ca5354def3d8fce243717141ce31e2c428701f6682bd2fafe15388214

WORKDIR /opt

### Pinned digests and commits for downloaded dependencies ###

# GCC digest
ENV GCC_ARM_SHA256=5adc2ee03904571c2de79d5cfc0f7fe2a5c5f54f44da5b645c17ee57b217f11f

# Nano S Secure SDK (https://github.com/rsksmart/rsk-powhsm-nanos-secure-sdk)
# Commit is tag nanos-1314-powhsm-v3 (https://github.com/rsksmart/rsk-powhsm-nanos-secure-sdk/releases/tag/nanos-1314-powhsm-v3)
ENV NANOS_SDK_COMMIT=4496b216fc5f619dc097a6b849aa4b88991a60fd
ENV NANOS_SDK_SHA256=3da88cfc67758adf0ef001c7374687181e2d41a8ec7f061be49322089a40c1ed

# Python pip wheel digest
ENV PIP_WHEEL_SHA256=217ae5161a0e08c0fb873858806e3478c9775caffce5168b50ec885e358c199d
# Pillow version and digest
ENV PILLOW_VERSION=6.2.2
ENV PILLOW_SHA256=e3a797a079ce289e59dbd7eac9ca3bf682d52687f718686857281475b7ca8e6a

# Ledger Blue (https://github.com/LedgerHQ/blue-loader-python)
# Commit is tag 0.1.31 (https://github.com/LedgerHQ/blue-loader-python/releases/tag/0.1.31)
ENV LEDGERBLUE_COMMIT=c65fdb6e61b1c96f693c3197737f5a628ce544ea
# Digests for hexParser.py and hashApp.py
ENV HEXPARSER_SHA256=e7f99cf684f957d76640f556b5e0c0bb61c70aeb46b8810dec319c6e98c97c2c
ENV HASHAPP_SHA256=caa87e60dbe443284f2dd3b16c31847eeb0a1d3d339538e7a51a544a45ffba77

RUN apt-get update && \
    apt-get install -y apt-utils && \
    apt-get install -y curl && \
    apt-get install -y build-essential=12.8ubuntu1 && \
    apt-get install -y clang-tools

RUN curl -L -o gcc-arm-none-eabi-9-2020-q2-update-x86_64-linux.tar.bz2 \
        https://developer.arm.com/-/media/Files/downloads/gnu-rm/9-2020q2/gcc-arm-none-eabi-9-2020-q2-update-x86_64-linux.tar.bz2 && \
    echo "$GCC_ARM_SHA256  gcc-arm-none-eabi-9-2020-q2-update-x86_64-linux.tar.bz2" | sha256sum -c - && \
    tar xjf gcc-arm-none-eabi-9-2020-q2-update-x86_64-linux.tar.bz2 && \
    rm -f gcc-arm-none-eabi-9-2020-q2-update-x86_64-linux.tar.bz2

RUN apt-get install -y clang-10=1:10.0.0-4ubuntu1 && \
    apt-get install -y clang-format-10=1:10.0.0-4ubuntu1 && \
    apt-get install -y gcc-multilib=4:9.3.0-1ubuntu2 g++-multilib=4:9.3.0-1ubuntu2 && \
    ln -s /usr/bin/clang-10 /usr/bin/clang

RUN curl -L -o nanos-1314.tar.gz https://github.com/rsksmart/rsk-powhsm-nanos-secure-sdk/archive/$NANOS_SDK_COMMIT.tar.gz && \
    echo "$NANOS_SDK_SHA256  nanos-1314.tar.gz" | sha256sum -c - && \
    mkdir nanos-secure-sdk-nanos-1314 && \
    tar xzf nanos-1314.tar.gz -C nanos-secure-sdk-nanos-1314 --strip-components=1 && \
    rm -f nanos-1314.tar.gz

RUN apt install -y python2 && \
    ln -s /usr/bin/python2 /usr/bin/python && \
    curl -L -o pip-20.3.4-py2.py3-none-any.whl \
        https://files.pythonhosted.org/packages/27/79/8a850fe3496446ff0d584327ae44e7500daf6764ca1a382d2d02789accf7/pip-20.3.4-py2.py3-none-any.whl && \
    echo "$PIP_WHEEL_SHA256  pip-20.3.4-py2.py3-none-any.whl" | sha256sum -c - && \
    python pip-20.3.4-py2.py3-none-any.whl/pip install --no-index pip-20.3.4-py2.py3-none-any.whl && \
    rm -f pip-20.3.4-py2.py3-none-any.whl

RUN echo "pillow==$PILLOW_VERSION --hash=sha256:$PILLOW_SHA256" > pillow-requirements.txt && \
    pip2 install --require-hashes -r pillow-requirements.txt && \
    rm -f pillow-requirements.txt

# Barebones hashApp from ledgerblue
RUN mkdir /opt/hashapp && \
    touch /opt/hashapp/__init__.py && \
    curl -L -o /opt/hashapp/hexParser.py \
        https://raw.githubusercontent.com/LedgerHQ/blue-loader-python/$LEDGERBLUE_COMMIT/ledgerblue/hexParser.py && \
    curl -L -o /opt/hashapp/hashApp.py \
        https://raw.githubusercontent.com/LedgerHQ/blue-loader-python/$LEDGERBLUE_COMMIT/ledgerblue/hashApp.py && \
    echo "$HEXPARSER_SHA256  /opt/hashapp/hexParser.py" | sha256sum -c - && \
    echo "$HASHAPP_SHA256  /opt/hashapp/hashApp.py" | sha256sum -c -

ENV BOLOS_SDK=/opt/nanos-secure-sdk-nanos-1314
ENV CLANGPATH=/usr/bin/
ENV GCCPATH=/opt/gcc-arm-none-eabi-9-2020-q2-update/bin/
ENV GCC_INCLUDE=/opt/gcc-arm-none-eabi-9-2020-q2-update/arm-none-eabi/include
