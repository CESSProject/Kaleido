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

By default Kaleido runs on port 8080, you can set the port to whatever you want by setting `KALEIDO_PORT` environment variable.
To map this TCP port in the container to the port on Docker host you can set `-p <DOCKER_HOST_PORT>:<KALEIDO_PORT>`. For example, if we want to map Container's port `8080` to our Docker host port `80` we can add `-p 80:8080`. 

```bash
docker run -v <PATH_TO_KALEIDO_ROOT_DIR>:/root/Kaleido -p 80:8080 --device <YOUR_ENCLAVE_DIR> --device <YOUR_PROVISION_DIR> -ti cesslab/sgx-rust
```

for example if the sgx driver is located in `/dev/sgx_enclave` and `/dev/sgx_provision` then run the following command

```bash
docker run -v <PATH_TO_KALEIDO_ROOT_DIR>:/root/Kaleido -p 80:8080 --device /dev/sgx_enclave --device /dev/sgx_provision -ti cesslab/sgx-rust
```

### To run the container in simulation mode

For testing and development purpose

```bash
docker run --env SGX_MODE=SW -v <PATH_TO_KALEIDO_ROOT_DIR>:/root/Kaleido -p 80:8080 -ti cesslab/sgx-rust
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

### Run Kaleido

> *NOTE:* To generate PoDR2 signing Key Pairs you can also set `ENCLAVE_KEY_SEED` by default its set to `TEST_SEED`. This will however, be removed in the future update, since keys will be dynamically generated within the enclave so that nobody can have access to it.

```bash
export ENCLAVE_KEY_SEED="TEST_SEED"
```

Optionally, you can also set logging and debugging envrionment variable. To do so set the follwing

```bash
export RUST_LOG="debug"
export RUST_BACKTRACE=1
```

To run Kaleido in enclave simulation mode set 
```bash
export SGX_MODE=SW      # SGX_MODE=HW for Hardware Mode
```

If you are running Kaleido in SGX(Hardware) mode you will have to start `AESM`, execute those commands in your terminal.
```bash
LD_LIBRARY_PATH=/opt/intel/sgx-aesm-service/aesm/
/opt/intel/sgx-aesm-service/aesm/aesm_service
```

Finally, To run Kaleido navigate to `/bin` and execute `app`

```bash
cd bin
./app
```

## Kaleido API Calls.

### `process_data`

**Description**: This function takes base64 encoded `data` for which **PoDR2** needs to be calculated. `block_size` and `segment_size` determines the size of each chunk of the `data` while calculating PoDR2. And the `callback_url` is the url where the computed PoDR2 result will be posted. 

**Request**
```bash
curl -H 'Content-Type: application/json' -X POST http://localhost/process_data -d '{"data":"aGk=", "block_size":10485, "segment_size":1, "callback_url":<REPLACE_WITH_CALLBACK_URL>}'
```

**Response**: The data will be posted back to the `callback_url` provided above with the following sample content.
```json
{
  "t": {
    "t0": {
      "name": "70FB321WFqzc9w67hcNF81rh2/b4T9lJKjy9YL8r8sA=",
      "n": 1,
      "u": [
        "QAK+f/glOhEIZfy16LX5K9n+pwE/sSg9+y/uNedJWq8B",
        "Pz7f+BOiRIUaRA4o3aQ7pUR61OKl5m4zyMPnXJ2L9VcB",
        "+5X5w9nbAWgkSj0zUE66aHVGSxDvKb/UPD/bwWmXFPQB"
      ]
    },
    "signature": "xNvKLcODuNqkEyPYqMK/+acPOQ+70SaSJP/nVnuEjHIA"
  },
  "sigmas": [
    "CDmNieOMKub3+DiFzssvnzOyXuaSjLhC1kUypab8dpkB"
  ],
  "pkey": "1IMbGs/VlFJ+x55igbsrPfWpONBAk+Dx4BqVnMMFL11WY2ROoraEESY2y9fHTrggvpHukH+wbSaTfbY+MinhRQA="
}
```
