#!/bin/bash

source ./utils.sh

function install_build_dep() {
  log_info "Installing Dependencies"

  # install dependencies
  apt update -y &&
    apt upgrade -y &&
    apt dist-upgrade -y &&
    apt install build-essential software-properties-common -y &&
    add-apt-repository ppa:ubuntu-toolchain-r/test -y &&
    apt update -y &&
    apt install gcc-9 g++-9 -y &&
    update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-9 60 --slave /usr/bin/g++ g++ /usr/bin/g++-9 &&
    update-alternatives --config gcc

  apt install -y autoconf \
    automake \
    libtool \
    bison \
    flex \
    libgmp3-dev \
    clang

  log_info "Installing SGX-GMP Library"

  # install sgx-gmp
  cd .. &&
    git clone https://github.com/intel/sgx-gmp &&
    cd sgx-gmp &&
    ./configure --enable-sgx --enable-static --disable-shared --enable-assembly &&
    make install &&
    cd .. && rm -rf sgx-gmp

  log_info "Installing SGX-PBC Library"

  # install pbc
  cd Kaleido/cess_pbc/pbc && \ 
  export SGX_TSTDC_CPPFLAGS=-I/usr/local/include &&
    ./bootstrap &&
    ./configure &&
    make install

  log_info "Building Kaleido"

  # Build Kaleido
  cd ../.. && make

  # Start AESM
  LD_LIBRARY_PATH=/opt/intel/sgx-aesm-service/aesm/
  /opt/intel/sgx-aesm-service/aesm/aesm_service
}
