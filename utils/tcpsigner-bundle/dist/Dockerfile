FROM debian:bookworm-slim@sha256:f70dc8d6a8b6a06824c92471a1a258030836b26b043881358b967bf73de7c5ab

RUN apt-get update && \
    apt-get install -y procps libsecp256k1-dev

WORKDIR /bundle

COPY bin/tcpsigner /bins/

COPY bin/manager_tcp.tgz /bins/manager_tcp.tgz
RUN tar xzf /bins/manager_tcp.tgz -C /bins > /dev/null 2>&1
RUN rm -f /bins/manager_tcp.tgz

COPY bin/entrypoint.sh /bins
RUN chmod ugo+x /bins/entrypoint.sh

CMD "/bins/entrypoint.sh"
