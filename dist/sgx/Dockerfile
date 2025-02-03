FROM debian:bookworm-slim@sha256:f70dc8d6a8b6a06824c92471a1a258030836b26b043881358b967bf73de7c5ab

WORKDIR /hsm2

RUN apt-get update && \
    apt-get install -y binutils gnupg2 curl

# Download and install libssl1.1 from debian main repository
RUN curl -L -o libssl1.1.deb  https://ftp.debian.org/debian/pool/main/o/openssl/libssl1.1_1.1.1w-0+deb11u1_amd64.deb && \
    dpkg -i libssl1.1.deb && \
    rm libssl1.1.deb

# Install SGX runtime dependencies
RUN echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' | tee /etc/apt/sources.list.d/intel-sgx.list && \
    echo 'deb [arch=amd64] http://azure.archive.ubuntu.com/ubuntu/ focal main restricted' | tee -a /etc/apt/sources.list.d/intel-sgx.list && \
    echo 'deb [arch=amd64] https://packages.microsoft.com/ubuntu/20.04/prod focal main' | tee -a /etc/apt/sources.list.d/intel-sgx.list && \
    gpg --keyserver keyserver.ubuntu.com --recv-keys 871920D1991BC93C 3B4FE6ACC0B21F32 EB3E94ADBE1229CF && \
    gpg --export --armor 871920D1991BC93C | apt-key add - && \
    gpg --export --armor 3B4FE6ACC0B21F32 | apt-key add - && \
    gpg --export --armor EB3E94ADBE1229CF | apt-key add - && \
    curl -fsSL https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add - && \
    apt-get update && \
    apt-get install -y libsgx-enclave-common libsgx-quote-ex libsgx-dcap-ql az-dcap-client
