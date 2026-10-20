FROM debian:bookworm-slim@sha256:f70dc8d6a8b6a06824c92471a1a258030836b26b043881358b967bf73de7c5ab

WORKDIR /hsm2

### Pinned digests, commits and key ids for downloaded dependencies ###

# Pinned digest for the libssl1.1 package
ENV LIBSSL_SHA256=aadf8b4b197335645b230c2839b4517aa444fd2e8f434e5438c48a18857988f7
# Full fingerprints of the repository signing keys
# Ubuntu Archive Automatic Signing Key (2012)
ENV UBUNTU_2012_KEY_FPR=790BC7277767219C42C86F933B4FE6ACC0B21F32
# Ubuntu Archive Automatic Signing Key (2018)
ENV UBUNTU_2018_KEY_FPR=F6ECB3762474EDA9D21B7022871920D1991BC93C
# Microsoft (Release signing)
ENV MICROSOFT_KEY_FPR=BC528686B50D79E339D3721CEB3E94ADBE1229CF
# Intel(R) Software Development Products
ENV INTEL_SGX_KEY_FPR=150434D1488BF80308B69398E5C7F0FA1C6C6C3C

RUN apt-get update && \
    apt-get install -y binutils gnupg2 curl

# Download and install libssl1.1 from debian main repository
RUN curl -L -o libssl1.1.deb  https://ftp.debian.org/debian/pool/main/o/openssl/libssl1.1_1.1.1w-0+deb11u1_amd64.deb && \
    echo "$LIBSSL_SHA256  libssl1.1.deb" | sha256sum -c - && \
    dpkg -i libssl1.1.deb && \
    rm libssl1.1.deb

# Fetch the repository signing keys and keep only the expected ones,
# selected by full fingerprint.
# Each repository then trusts only its own keyring
RUN mkdir -p /etc/apt/keyrings && \
    gpg --keyserver hkps://keyserver.ubuntu.com --recv-keys \
        $UBUNTU_2012_KEY_FPR $UBUNTU_2018_KEY_FPR $MICROSOFT_KEY_FPR && \
    curl -fsSL https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | gpg --import && \
    gpg --export $UBUNTU_2012_KEY_FPR $UBUNTU_2018_KEY_FPR > /etc/apt/keyrings/ubuntu-archive.gpg && \
    gpg --export $MICROSOFT_KEY_FPR > /etc/apt/keyrings/microsoft.gpg && \
    gpg --export $INTEL_SGX_KEY_FPR > /etc/apt/keyrings/intel-sgx.gpg && \
    gpg --no-default-keyring --keyring /etc/apt/keyrings/ubuntu-archive.gpg --list-keys \
        $UBUNTU_2012_KEY_FPR $UBUNTU_2018_KEY_FPR && \
    gpg --no-default-keyring --keyring /etc/apt/keyrings/microsoft.gpg --list-keys $MICROSOFT_KEY_FPR && \
    gpg --no-default-keyring --keyring /etc/apt/keyrings/intel-sgx.gpg --list-keys $INTEL_SGX_KEY_FPR

# Install SGX runtime dependencies
# (the Azure Ubuntu mirror does not serve HTTPS; its packages are verified
# through the archive signature)
RUN echo 'deb [arch=amd64 signed-by=/etc/apt/keyrings/intel-sgx.gpg] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' | tee /etc/apt/sources.list.d/intel-sgx-runtime.list && \
    echo 'deb [arch=amd64 signed-by=/etc/apt/keyrings/ubuntu-archive.gpg] http://azure.archive.ubuntu.com/ubuntu/ focal main restricted' | tee -a /etc/apt/sources.list.d/intel-sgx-runtime.list && \
    echo 'deb [arch=amd64 signed-by=/etc/apt/keyrings/microsoft.gpg] https://packages.microsoft.com/ubuntu/20.04/prod focal main' | tee -a /etc/apt/sources.list.d/intel-sgx-runtime.list && \
    apt-get update && \
    apt-get install -y libsgx-enclave-common libsgx-quote-ex libsgx-dcap-ql az-dcap-client
