FROM rust:1.75 as builder

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -yq \
ca-certificates coreutils curl git make mercurial \
build-essential clang llvm libclang-dev lld \
gyp ninja-build pkg-config zlib1g-dev openssl libssl-dev libtss2-dev

WORKDIR /usr/src/ohttp
COPY . .
RUN cargo install --path ohttp-client

FROM ubuntu:22.04
RUN apt-get update && apt-get install -y ca-certificates curl jq openssl libssl-dev libtss2-dev && rm -rf /var/lib/apt/lists/*

# RUN apt-get update && \
#     apt-get install -y ca-certificates curl jq openssl libssl-dev libtss2-dev && \
#     apt-get install -y wget && \
#     wget http://security.ubuntu.com/ubuntu/pool/main/o/openssl1.1/openssl1.1_1.1.1f-1ubuntu2.16_amd64.deb && \
#     wget http://security.ubuntu.com/ubuntu/pool/main/o/openssl1.1/libssl1.1_1.1.1f-1ubuntu2.16_amd64.deb && \
#     dpkg -i openssl1.1_1.1.1f-1ubuntu2.16_amd64.deb libssl1.1_1.1.1f-1ubuntu2.16_amd64.deb && \
#     rm -rf /var/lib/apt/lists/*

COPY ./ohttp-server/ca.sh /usr/local/bin
COPY ./examples ./examples
COPY --from=builder /usr/local/cargo/bin/ohttp-client /usr/local/bin/ohttp-client
COPY --chmod=755 ./docker/client/run.sh .
CMD ["./run.sh"]