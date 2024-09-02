FROM openenclavedockerregistry.azurecr.io/oetools-20.04:2023.11.21100

# Install dependencies
RUN apt-get update && \
    apt-get install -y apt-utils vim && \
    apt-get install -y tar && \
    apt-get install -y xz-utils && \
    apt-get install -y curl && \
    apt-get install -y git && \
    apt-get install -y clang-11 && \
    apt-get install -y libssl-dev && \
    apt-get install -y gdb && \
    apt-get install -y libsgx-enclave-common && \
    apt-get install -y libsgx-quote-ex && \
    apt-get install -y libprotobuf17 && \
    apt-get install -y libsgx-dcap-ql && \
    apt-get install -y libsgx-dcap-ql-dev && \
    apt-get install -y az-dcap-client && \
    apt-get install -y open-enclave && \
    apt-get install -y gcc && \
    apt-get install -y make

# Create directory to host symlinks to Open Enclave static libraries
ENV SGX_STATIC_LIBS=/opt/openenclave-libs
ENV SGX_SECP256K1=/opt/secp256k1

# Build libsecp256k1 for Open Enclave
RUN curl -L -o secp256k1.tar.gz \
    https://github.com/bitcoin-core/secp256k1/archive/refs/tags/v0.4.0.tar.gz && \
    mkdir -p $SGX_SECP256K1  && \
    tar -xzf secp256k1.tar.gz --strip-components=1 -C $SGX_SECP256K1 && \
    rm -f secp256k1.tar.gz && \
    cd $SGX_SECP256K1 && \
    ./autogen.sh && \
    . /opt/openenclave/share/openenclave/openenclaverc && \
    ./configure --disable-tests --disable-benchmark --disable-exhaustive-tests CC=gcc CFLAGS="-std=c11 $(pkg-config oeenclave-gcc --cflags)" && \
    make && \
    mkdir -p $SGX_STATIC_LIBS && \
    ln -s $(realpath .libs/libsecp256k1.a) $SGX_STATIC_LIBS/libsecp256k1.a

# SGX environment setup command
ENV SGX_ENVSETUP="source /opt/openenclave/share/openenclave/openenclaverc"
