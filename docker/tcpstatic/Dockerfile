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

