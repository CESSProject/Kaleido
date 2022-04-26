# Kaleido

# Prerequisites

* #### Docker
* #### Intel SGX OOT 2.11.0 Driver or DCAP 1.36.2 Driver
* #### Intel SGX PSW
* #### Rust nightly-2020-10-25
* #### [SGX enabled PBC library](./cess_pbc/pbc/) - comes preinstalled with docker image
* #### [SGX-enabled GMP library](https://github.com/intel/sgx-gmp) - comes preinstalled with docker image

NOTE: Please install sgx-gmp uder default directory i.e. `/usr/local/`

### Pulling a Pre-Built Docker Container
We assume that you have [correctly installed docker](https://docs.docker.com/get-docker/):

First, pull the docker container, the below command will download the `latest`:
```
docker pull demochiang/cess_sgx:0.3.1
```

### Running with Intel SGX Driver

#### To run the container with OOT SGX driver, run:
```
docker run -v <PATH_TO_KALEIDO_ROOT_DIR>:/root/Kaleido --device /dev/isgx -ti demochiang/cess_sgx:0.3.1
```

#### To run the container with DCAP SGX driver:
Check your `/dev/` directory for `/dev/sgx_enclave` and `/dev/sgx_provision` 
or 
`/dev/sgx/enclave` and `/dev/sgx/provision`
and replace `<YOUR_ENCLAVE_DIR>` and `<YOUR_PROVISION_DIR>` with the your directory respectively.

```
docker run -v <PATH_TO_KALEIDO_ROOT_DIR>:/root/Kaleido --device <YOUR_ENCLAVE_DIR> --device <YOUR_PROVISION_DIR> -ti demochiang/cess_sgx:0.3.1
```

for example if the sgx driver is located in `/dev/sgx_enclave` and `/dev/sgx_provision` then run the following command 
```
docker run -v <PATH_TO_KALEIDO_ROOT_DIR>:/root/Kaleido --device /dev/sgx_enclave --device /dev/sgx_provision -ti demochiang/cess_sgx:0.3.1
```

#### To run the container in simulation mode:
For testing and development purpose
```
docker run --env SGX_MODE=SW -v <PATH_TO_KALEIDO_ROOT_DIR>:/root/Kaleido -ti demochiang/cess_sgx:0.3.1
```

# Build the Source Code

## Install GMP
Follow the instructions at [SGX-enabled GMP library](https://github.com/intel/sgx-gmp) to install GMP library. We recommend you not to set the `--prefix` parameter while configuring the library. This will by default install the library uder `/usr/local/` which is the requirement of Kaleido.

## Build SGX-enabled PBC Library

SGX compatible PBC source code can be found under [cess_pbc/pbc](./cess_pbc/pbc). To build the library please follow the instructions below.

You may set the following environment before executing the following commands

```
export SGX_TSTDC_CPPFLAGS=-I/usr/local/include
```

```bash
cd cess_pbc/pbc
./bootstrap
./configure
make
make install
```

## Build Kaleido

First `cd` back to Kaleido root directory 
```
cd ../..
``` 
then run the following command to build Kaleido
```
make
```
finally to run
```
cd bin
./app
```

Optionally you can set `SGX_MODE` environment variable before running `make` command to run in simulation mode
```
export SGX_MODE=SW
```