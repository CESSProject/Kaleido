FROM cesslab/cess-sgxrust-env:latest

RUN set -eux; \
    add-apt-repository ppa:ubuntu-toolchain-r/test -y && \
    apt-get update -y && \
    apt-get install -y build-essential software-properties-common gcc-9 g++-9 libgmp3-dev clang && \
    \
    ln -s /opt/sgxsdk /opt/intel/sgxsdk \
    && git clone https://github.com/intel/sgx-gmp \
    && cd sgx-gmp \
    && ./configure --enable-sgx --enable-static --disable-shared --enable-assembly \
    && make install \
    && cd .. \
    && rm -rf sgx-gmp \
    \
    && git clone https://github.com/tehsunnliu/pbc-sgx \
    && cd pbc-sgx \ 
    && export SGX_TSTDC_CPPFLAGS=-I/usr/local/include \
    && ./bootstrap \
    && ./configure \
    && make install \
    && cd .. \
    && rm -rf pbc-sgx \
    && rm -rf /var/lib/apt/lists/*
