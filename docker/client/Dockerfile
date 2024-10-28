FROM rust:1.75 AS builder

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -yq \
ca-certificates coreutils curl git make mercurial \
build-essential clang llvm libclang-dev lld \
gyp ninja-build pkg-config zlib1g-dev libssl-dev

WORKDIR /usr/src/ohttp
COPY . .
RUN cargo install --path ohttp-client --debug

FROM ubuntu:22.04
RUN apt-get update && apt-get install -y ca-certificates openssl curl jq && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/cargo/bin/ohttp-client /usr/local/bin/ohttp-client
ENV RUST_BACKTRACE=1
ENV RUST_LOG=info
ENTRYPOINT [ "/usr/local/bin/ohttp-client" ]