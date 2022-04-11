#!/bin/sh
apt update && apt install -y --no-install-recommends \
                bison \
                flex \
                libgmp3-dev \
                clang \
    && rm -rf /var/lib/apt/lists/*

export PBC_VERSION=0.5.14

set -ex \
        \
        && wget -O pbc.tar.gz "https://crypto.stanford.edu/pbc/files/pbc-$PBC_VERSION.tar.gz" \
        && mkdir -p /usr/src/pbc \
        && tar -xzC /usr/src/pbc --strip-components=1 -f pbc.tar.gz \
        && rm pbc.tar.gz \
	    \
	    && cd /usr/src/pbc \
        && ./configure \
        && make \
        && make install \
        && rm -rf /usr/src/pbc \
        && cd ~/Kaleido \
        && make

LD_LIBRARY_PATH=/opt/intel/sgx-aesm-service/aesm/
/opt/intel/sgx-aesm-service/aesm/aesm_service