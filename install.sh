#!/bin/sh
cd ..
git clone https://github.com/blynn/pbc
cd pbc
apt update -y && \
    apt upgrade -y && \
    apt dist-upgrade -y && \
    apt install build-essential software-properties-common -y && \
    add-apt-repository ppa:ubuntu-toolchain-r/test -y && \
    apt update -y && \
    apt install gcc-9 g++-9 -y && \
    update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-9 60 --slave /usr/bin/g++ g++ /usr/bin/g++-9 && \
    update-alternatives --config gcc

apt install -y autoconf \
        automake \
        libtool \
        bison \
        flex \
        libgmp3-dev \
        clang \
    && rm -rf /var/lib/apt/lists/* \
    && autoreconf --verbose --install --force \
    && ./configure \
    && make \
    && make install \
    && cd .. \
    && rm -rf pbc

LD_LIBRARY_PATH=/opt/intel/sgx-aesm-service/aesm/
/opt/intel/sgx-aesm-service/aesm/aesm_service