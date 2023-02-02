FROM ubuntu:20.04

WORKDIR /opt

RUN apt-get update && \
    apt-get install -y apt-utils && \
    apt-get install -y curl && \
    apt-get install -y build-essential=12.8ubuntu1 && \
    apt-get install -y clang-tools

RUN curl -L -o gcc-arm-none-eabi-9-2020-q2-update-x86_64-linux.tar.bz2 \
        https://developer.arm.com/-/media/Files/downloads/gnu-rm/9-2020q2/gcc-arm-none-eabi-9-2020-q2-update-x86_64-linux.tar.bz2 && \
    tar xjf gcc-arm-none-eabi-9-2020-q2-update-x86_64-linux.tar.bz2 && \
    rm -f gcc-arm-none-eabi-9-2020-q2-update-x86_64-linux.tar.bz2

RUN apt-get install -y clang-10=1:10.0.0-4ubuntu1 && \
    apt-get install -y clang-format-10=1:10.0.0-4ubuntu1 && \
    apt-get install -y gcc-multilib=4:9.3.0-1ubuntu2 g++-multilib=4:9.3.0-1ubuntu2 && \
    ln -s /usr/bin/clang-10 /usr/bin/clang

RUN curl -L -o nanos-1314.tar.gz https://github.com/LedgerHQ/nanos-secure-sdk/archive/nanos-1314.tar.gz && \
    tar xzf nanos-1314.tar.gz && \
    rm -f nanos-1314.tar.gz

RUN apt install -y python2 && \
    ln -s /usr/bin/python2 /usr/bin/python && \
    curl -o get-pip.py https://bootstrap.pypa.io/pip/2.7/get-pip.py && \
    python get-pip.py && \
    rm -f get-pip.py

RUN pip2 install pillow

# Barebones hashApp from ledgerblue 0.1.31 (https://github.com/LedgerHQ/blue-loader-python)
RUN mkdir /opt/hashapp && \
    touch /opt/hashapp/__init__.py && \
    curl -L -o /opt/hashapp/hexParser.py \
        https://raw.githubusercontent.com/LedgerHQ/blue-loader-python/0.1.31/ledgerblue/hexParser.py && \
    curl -L -o /opt/hashapp/hashApp.py \
        https://raw.githubusercontent.com/LedgerHQ/blue-loader-python/0.1.31/ledgerblue/hashApp.py

# Patched version of os.h with APDU_BUFFER reduced from 255 to 80 bytes
COPY os.h.patch nanos-secure-sdk-nanos-1314/include/os.h.patch
RUN patch nanos-secure-sdk-nanos-1314/include/os.h nanos-secure-sdk-nanos-1314/include/os.h.patch
RUN rm -f nanos-secure-sdk-nanos-1314/include/os.h.patch

# Patched version of usbd_conf.h to prevent compiler warnings
COPY usbd_conf.h.patch nanos-secure-sdk-nanos-1314/lib_stusb/usbd_conf.h.patch
RUN patch nanos-secure-sdk-nanos-1314/lib_stusb/usbd_conf.h nanos-secure-sdk-nanos-1314/lib_stusb/usbd_conf.h.patch
RUN rm -f nanos-secure-sdk-nanos-1314/lib_stusb/usbd_conf.h.patch

# Patched version of os_io_seproxyhal.h to prevent compiler warnings
COPY os_io_seproxyhal.h.patch nanos-secure-sdk-nanos-1314/include/os_io_seproxyhal.h.patch
RUN patch nanos-secure-sdk-nanos-1314/include/os_io_seproxyhal.h nanos-secure-sdk-nanos-1314/include/os_io_seproxyhal.h.patch
RUN rm -f nanos-secure-sdk-nanos-1314/include/os_io_seproxyhal.h.patch

ENV BOLOS_SDK=/opt/nanos-secure-sdk-nanos-1314
ENV CLANGPATH=/usr/bin/
ENV GCCPATH=/opt/gcc-arm-none-eabi-9-2020-q2-update/bin/
ENV GCC_INCLUDE=/opt/gcc-arm-none-eabi-9-2020-q2-update/arm-none-eabi/include
