# Kaleido

## Prerequisites

* **Docker**

* **Intel SGX OOT 2.11.0 Driver or DCAP 1.36.2 Driver**

* **Intel SGX PSW**

* **Rust nightly-2020-10-25**

* **[SGX-enabled PBC library](https://github.com/tehsunnliu/pbc-sgx) - comes preinstalled with docker image**

* **[SGX-enabled GMP library](https://github.com/intel/sgx-gmp) - comes preinstalled with docker image**

NOTE: Please install sgx-gmp uder default directory i.e. `/usr/local/`

## Pulling a Pre-Built Docker Container

We assume that you have [correctly installed docker](https://docs.docker.com/get-docker/):

First, pull the docker container, the below command will download the `latest`:

```bash
docker pull cesslab/sgx-rust
```

## Running with Intel SGX Driver

### To run the container with OOT SGX driver, run

```bash
docker run -v <PATH_TO_KALEIDO_ROOT_DIR>:/root/Kaleido --device /dev/isgx -ti cesslab/sgx-rust
```

### To run the container with DCAP SGX driver

Check your `/dev/` directory for `/dev/sgx_enclave` and `/dev/sgx_provision`
or
`/dev/sgx/enclave` and `/dev/sgx/provision`
and replace `<YOUR_ENCLAVE_DIR>` and `<YOUR_PROVISION_DIR>` with the your directory respectively.

```bash
docker run -v <PATH_TO_KALEIDO_ROOT_DIR>:/root/Kaleido --device <YOUR_ENCLAVE_DIR> --device <YOUR_PROVISION_DIR> -ti cesslab/sgx-rust
```

for example if the sgx driver is located in `/dev/sgx_enclave` and `/dev/sgx_provision` then run the following command

```bash
docker run -v <PATH_TO_KALEIDO_ROOT_DIR>:/root/Kaleido --device /dev/sgx_enclave --device /dev/sgx_provision -ti cesslab/sgx-rust
```

### To run the container in simulation mode

For testing and development purpose

```bash
docker run --env SGX_MODE=SW -v <PATH_TO_KALEIDO_ROOT_DIR>:/root/Kaleido -ti cesslab/sgx-rust
```

## Build the Source Code

### Install GMP

Follow the instructions at [SGX-enabled GMP library](https://github.com/intel/sgx-gmp) to install GMP library. We recommend you not to set the `--prefix` parameter while configuring the library. This will by default install the library uder `/usr/local/` which is the requirement of Kaleido.

### Install SGX-enabled PBC Library

Follow the instructions at [SGX-enabled PBC library](https://github.com/tehsunnliu/pbc-sgx) to install PBC library.

### Build Kaleido

First `cd` back to Kaleido root directory

```bash
cd ../..
```

then run the following command to build Kaleido

```bash
make
```

finally to run

```bash
cd bin
./app
```

Optionally you can set `SGX_MODE` environment variable before running `make` command to run in simulation mode

```bash
export SGX_MODE=SW
```
