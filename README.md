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

By default Kaleido runs on port 8080, you can set the port to whatever you want by setting `KALEIDO_PORT` environment variable.
To map this TCP port in the container to the port on Docker host you can set `-p <DOCKER_HOST_PORT>:<KALEIDO_PORT>`. For example, if we want to map Container's port `8080` to our Docker host port `80` we can add `-p 80:8080`. 

### To run the container with OOT SGX driver, run

```bash
docker run -v <PATH_TO_KALEIDO_ROOT_DIR>:/root/Kaleido -p 80:8080 --device /dev/isgx -ti cesslab/sgx-rust
```

### To run the container with DCAP SGX driver

Check your `/dev/` directory for `/dev/sgx_enclave` and `/dev/sgx_provision`
or
`/dev/sgx/enclave` and `/dev/sgx/provision`
and replace `<YOUR_ENCLAVE_DIR>` and `<YOUR_PROVISION_DIR>` with the your directory respectively.

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

Apply for Intel Remote Attestation API keys at [Intel IAS (EPID Attestation) Service](https://api.portal.trustedservices.intel.com/EPID-attestation). Make sure SPID is **linkable**

Set SPID and API key received from Intel

```bash
export IAS_SPID=<YOUR_SPID>
export IAS_API_KEY=<YOUR_PRIMARY_KEY_OR_SECONDARY_KEY>
```

First `cd` back to Kaleido root directory

```bash
cd ../..
```

then run the following command to build Kaleido. By default `make` builds in Hardware Mode `SGX_MODE=HW` to build in Software Mode uncomment `SGX_MODE=SW`.

```bash
make #SGX_MODE=SW
```

### Run Kaleido

Optionally, you can also set logging and debugging envrionment variable. To do so set the follwing

```bash
export RUST_LOG="debug"
export RUST_BACKTRACE=1
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

**Description**: This function need to pass `file_path` to be processed. `block_size`determines the size of each chunk of the `data` while calculating PoDR2. And the `callback_url` is the url where the computed PoDR2 result will be posted. 

**Request**

```bash
curl -H 'Content-Type: application/json' -X POST http://localhost:80/process_data -d '{"file_path":"<Path Of File To Be Processed>", "block_size":10, "callback_url":"<REPLACE_WITH_CALLBACK_URL>"}'
```

**Response**: The data will be posted back to the `callback_url` provided above with the following sample content.

```json
{
  "sigmas": [
    "36193ad3116bfd17e01ecb9ffcf0816d",
  ],
  "tag": {
    "t": {
      "n": 5,
      "enc": [],
      "file_hash": []
    },
    "mac_t0": []
  },
  "status": {
    "status_code": 10000,
    "status_msg": "Sig gen successful!"
  }
}
```


## Code Walk Through

### Enclave initialization

When the node starts, it needs to instantiate an enclave and obtain its id as the business enclave, [code](https://github.com/CESSProject/Kaleido/blob/133caa3154aa0b79492fd1f5c8e59a4adc8723e9/app/src/main.rs#L49).

### Enclave environment initialization

PBC key initialization:

* The initialization of the PBC key occurs when the kaleido node starts. When kaleido starts, it first calls the [init_pairings function](https://github.com/CESSProject/Kaleido/blob/133caa3154aa0b79492fd1f5c8e59a4adc8723e9/enclave/src/pbc.rs#L6) under the pbc file in the enclave.
* Secondly, the init_pairings function will use rust-ffi to call the C++ function [init_pairing method](https://github.com/CESSProject/Kaleido/blob/133caa3154aa0b79492fd1f5c8e59a4adc8723e9/cess_pbc/src/pbc/pbc_intf.cpp#L92) which is located in the cess_pbc package. The PBC key pair is initialized.
* The selected security parameters and initial generators are located under the cess_curve file,[code](https://github.com/CESSProject/Kaleido/blob/133caa3154aa0b79492fd1f5c8e59a4adc8723e9/cess_curve/src/config.rs#L8).

Enclave memory initialization:

* Convert the enclave memory max to decimal,[code](https://github.com/CESSProject/Kaleido/blob/133caa3154aa0b79492fd1f5c8e59a4adc8723e9/enclave/src/lib.rs#L206)
* Add the maximum memory value to the memory global variable field in an atomic operation,[code](https://github.com/CESSProject/Kaleido/blob/133caa3154aa0b79492fd1f5c8e59a4adc8723e9/enclave/src/lib.rs#L209)

### Keep the key consistent

* Start the mutual attestation server port and wait for other nodes to obtain their PBC keys,[code](https://github.com/CESSProject/Kaleido/blob/133caa3154aa0b79492fd1f5c8e59a4adc8723e9/app/src/main.rs#L149).
* The server port passes the socket handle to the enclave for processing, and the enclave obtains the remote attestation report,[code](https://github.com/CESSProject/Kaleido/blob/133caa3154aa0b79492fd1f5c8e59a4adc8723e9/enclave/src/secret_exchange/mod.rs#L567).
* The server port adds the remote authentication report certificate to the TLS,[code](https://github.com/CESSProject/Kaleido/blob/133caa3154aa0b79492fd1f5c8e59a4adc8723e9/enclave/src/secret_exchange/mod.rs#L652).
* The node needs to judge whether it is the first node to start. Currently, it is judged whether it is the first node by reading the configuration file,[code](https://github.com/CESSProject/Kaleido/blob/133caa3154aa0b79492fd1f5c8e59a4adc8723e9/app/src/main.rs#L191).
* If it is not the first node, start the client port to request the PBC key from the configuration file address,[code](https://github.com/CESSProject/Kaleido/blob/133caa3154aa0b79492fd1f5c8e59a4adc8723e9/app/src/main.rs#L232).

### File proof computing function

* The initialization file proof the computation interface,[code](https://github.com/CESSProject/Kaleido/blob/133caa3154aa0b79492fd1f5c8e59a4adc8723e9/app/src/main.rs#L126).
* The entry of the file proof calculation method needs to pass in the block size and segment size of the PBC key pair,[code](https://github.com/CESSProject/Kaleido/blob/133caa3154aa0b79492fd1f5c8e59a4adc8723e9/enclave/src/lib.rs#L298).
* The entry of the calculation method for the file signature when the file proof is calculated,[code](https://github.com/CESSProject/Kaleido/blob/133caa3154aa0b79492fd1f5c8e59a4adc8723e9/enclave/src/podr2_proof_commit.rs#L118).
* After the file proof the calculated result, send the file proof result to the callback address method entry,[code](https://github.com/CESSProject/Kaleido/blob/133caa3154aa0b79492fd1f5c8e59a4adc8723e9/enclave/src/lib.rs#L333).
