FROM ubuntu:18.04

ENV DEBIAN_FRONTEND=noninteractive

RUN set -eux; \
    apt-get update && \
    apt-get install -y autoconf automake bison build-essential cmake curl dpkg-dev expect flex gcc-8 gdb git git-core gnupg kmod libboost-system-dev libboost-thread-dev libcurl4-openssl-dev libiptcdata0-dev libjsoncpp-dev liblog4cpp5-dev libprotobuf-c0-dev libprotobuf-dev libssl-dev libtool libxml2-dev ocaml ocamlbuild pkg-config protobuf-compiler python texinfo uuid-dev vim wget dkms gnupg2 apt-transport-https software-properties-common && \
    rm -rf /var/lib/apt/lists/* && \
    rm -rf /var/cache/apt/archives/*

#### BinUtils ####
ENV BINUTILS_DIST="ubuntu18.04"
ENV LD_LIBRARY_PATH=/usr/lib:/usr/local/lib
ENV LD_RUN_PATH=/usr/lib:/usr/local/lib
ADD 02_binutils.sh /root
RUN bash /root/02_binutils.sh

#### SGX SDK ####
ENV SDK_DIST="INTEL_BUILT"
ENV SDK_URL="https://download.01.org/intel-sgx/sgx-linux/2.15.1/distro/ubuntu18.04-server/sgx_linux_x64_sdk_2.15.101.1.bin"
ADD 03_sdk.sh /root
RUN bash /root/03_sdk.sh
    
#### SGX PSW ####
ENV CODENAME        bionic
ENV VERSION         2.15.101.1-bionic1
ENV DCAP_VERSION    1.12.101.1-bionic1
ADD 04_psw.sh /root
RUN bash /root/04_psw.sh

#### Rust ####
ENV RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo RUST_VERSION=1.62.1 PATH=/usr/local/cargo/bin:$PATH
ADD 05_rust.sh /root
RUN bash /root/05_rust.sh

ENV DEBIAN_FRONTEND=
ENV CODENAME=
ENV VERSION=

WORKDIR /root
