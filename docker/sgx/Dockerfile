FROM openenclavedockerregistry.azurecr.io/oetools-20.04:2024.10.2391@sha256:f9fc664daa4e479fa8778eff6afb4b0139b125ca006c924dc70ba5625726d608

# Install dependencies
RUN apt-get update && \
    apt-get install -y apt-utils vim && \
    apt-get install -y tar && \
    apt-get install -y curl && \
    apt-get install -y open-enclave=0.19.4 && \
    apt-get install -y clang-tools && \
    apt-get install -y make

# Create directory to host symlinks to Open Enclave static libraries
ENV SGX_STATIC_LIBS=/opt/openenclave-libs
ENV SGX_SECP256K1=/opt/secp256k1

### Pinned digests and commits for downloaded dependencies ###

# libsecp256k1 (https://github.com/bitcoin-core/secp256k1)
# Commit is tag v0.4.0 (https://github.com/bitcoin-core/secp256k1/releases/tag/v0.4.0)
ENV SECP256K1_COMMIT=199d27cea32203b224b208627533c2e813cd3b21
ENV SECP256K1_SHA256=3ffdeed78c7bebfe6cbd87bbe99d36982e92a6893d1e8b4dd4fdbf35a8811320

# Build libsecp256k1 for Open Enclave
RUN curl -L -o secp256k1.tar.gz \
    https://github.com/bitcoin-core/secp256k1/archive/$SECP256K1_COMMIT.tar.gz && \
    echo "$SECP256K1_SHA256  secp256k1.tar.gz" | sha256sum -c - && \
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
