FROM debian:bookworm@sha256:c66c66fac809bfb56a8001b12f08181a49b6db832d2c8ddabe22b6374264055f

WORKDIR /hsm2

RUN apt-get update && \
    apt-get install -y apt-utils vim procps curl build-essential=12.9 make cmake

# Create directory to host symlinks to static libraries
ENV TCPSIGNER_STATIC_LIBS=/opt/tcpsigner-libs
RUN mkdir $TCPSIGNER_STATIC_LIBS

# Build libsecp256k1
ENV TCPSIGNER_SECP256K1=/opt/secp256k1
RUN curl -L -o secp256k1.tar.gz \
    https://github.com/bitcoin-core/secp256k1/archive/refs/tags/v0.4.0.tar.gz && \
    mkdir $TCPSIGNER_SECP256K1 && \
    tar -xzf secp256k1.tar.gz --strip-components=1 -C $TCPSIGNER_SECP256K1 && \
    rm -f secp256k1.tar.gz && \
    cd $TCPSIGNER_SECP256K1 && \
    mkdir build && cd build && \
    cmake .. -DSECP256K1_DISABLE_SHARED=ON && \
    make && \
    ln -s $(realpath src/libsecp256k1.a) $TCPSIGNER_STATIC_LIBS/libsecp256k1.a

# Build mbedtls
ENV TCPSIGNER_MBEDTLS=/opt/mbedtls
RUN curl -L -o mbedtls.tar.bz2 \
    https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.5/mbedtls-3.6.5.tar.bz2 && \
    mkdir $TCPSIGNER_MBEDTLS && \
    tar -xjf mbedtls.tar.bz2 --strip-components=1 -C $TCPSIGNER_MBEDTLS && \
    rm -f mbedtls.tar.bz2 && \
    cd $TCPSIGNER_MBEDTLS && \
    cmake -DCMAKE_BUILD_TYPE=Release -DENABLE_TESTING=Off . && \
    cmake --build . && \
    ln -s $(realpath library/libmbedtls.a) $TCPSIGNER_STATIC_LIBS/libmbedtls.a && \
    ln -s $(realpath library/libmbedcrypto.a) $TCPSIGNER_STATIC_LIBS/libmbedcrypto.a && \
    ln -s $(realpath library/libmbedx509.a) $TCPSIGNER_STATIC_LIBS/libmbedx509.a

