FROM debian:stretch-slim

RUN apt-get update && \
    apt-get install -y procps libsecp256k1-dev

WORKDIR /bundle

COPY bin/tcpsigner /bins/

COPY bin/manager-tcp.tgz /bins/manager-tcp.tgz
RUN tar xzf /bins/manager-tcp.tgz -C /bins > /dev/null 2>&1
RUN rm -f /bins/manager-tcp.tgz

COPY bin/entrypoint.sh /bins
RUN chmod ugo+x /bins/entrypoint.sh

CMD "/bins/entrypoint.sh"
