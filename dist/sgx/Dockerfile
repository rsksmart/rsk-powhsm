FROM debian:bookworm-slim

WORKDIR /hsm2

RUN apt-get update && \
    apt-get install -y binutils gnupg2 curl wget

# Download and install libssl1.1 from debian main repository
RUN curl -L -o libssl1.1.deb  https://ftp.debian.org/debian/pool/main/o/openssl/libssl1.1_1.1.1w-0+deb11u1_amd64.deb && \
    dpkg -i libssl1.1.deb && \
    rm libssl1.1.deb

# Install SGX runtime dependencies
RUN echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' | tee /etc/apt/sources.list.d/intel-sgx.list && \
    wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add - && \
    apt-get update && \
    apt-get install libsgx-enclave-common
