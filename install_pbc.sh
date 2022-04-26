#!/bin/sh
cd repository/sgx-gmp
./configure --enable-static --disable-shared --enable-assembly --enable-sgx #--prefix=/opt/sgxsdk
make
make install 
cd ..
git clone https://github.com/fishermano/QShield-v1
cd repository/QShield-v1/tpl/pbc
./bootstrap 
export SGX_TSTDC_CPPFLAGS=-I/usr/local/include
./configure --enable-sgx-simulation #--prefix=/opt/sgxsdk
make
make install