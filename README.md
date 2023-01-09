# Kaleido

## Prerequisites

* **Docker**

* **Intel SGX OOT 2.11.0 Driver or DCAP 1.36.2 Driver**

* **Intel SGX PSW**

* **Rust nightly-2020-10-25**

* **[SGX-enabled PBC library](https://github.com/tehsunnliu/pbc-sgx) - comes preinstalled with docker image**

* **[SGX-enabled GMP library](https://github.com/intel/sgx-gmp) - comes preinstalled with docker image**

NOTE: Please install sgx-gmp uder default directory i.e. `/usr/local/`

## Clone kaleido source code

Download the source code of kaleido, command:

```shell
git clone https://github.com/CESSProject/Kaleido.git
```

## Install the sgx driver

The [Kaleido/scripts](https://github.com/CESSProject/Kaleido/tree/main/scripts) contains all the scripts required to install the SGX driver and other dependencies. You can run the following command to see the functionality provided by the script

```shell
cd scripts
./install help
```

Please install the sgx driver on your instance first.To install SGX driver navigate to the Kaleido/scripts directory and execute the following command

```shell
# For DCAP driver
./install sgx dcap

# For OOT driver
./install sgx isgx
```



## Way to run kaleido

### Build from source code(Recommended ❌)(Join CESS network ❌)

#### 1.Pulling a Pre-Built Docker Container

We assume that you have [correctly installed docker](https://docs.docker.com/get-docker/):

First, pull the docker container, the below command will download the `latest`:

```shell
docker pull cesslab/sgx-rust
```



#### 2.Running image with Intel SGX Driver

By default Kaleido runs on port 8080, you can set the port to whatever you want by setting `KALEIDO_PORT` environment variable.
To map this TCP port in the container to the port on Docker host you can set `-p <DOCKER_HOST_PORT>:<KALEIDO_PORT>`. For example, if we want to map Container's port `8080` to our Docker host port `80` we can add `-p 80:8080`. 

* To run the container with OOT SGX driver, run

  ```shell
  docker run -v <PATH_TO_KALEIDO_ROOT_DIR>:/root/Kaleido -p 80:8080 --device /dev/isgx  -v /:/sgx -ti cesslab/sgx-rust
  ```

* To run the container with DCAP SGX driver

  Check your `/dev/` directory for `/dev/sgx_enclave` and `/dev/sgx_provision`
  or
  `/dev/sgx/enclave` and `/dev/sgx/provision`
  and replace `<YOUR_ENCLAVE_DIR>` and `<YOUR_PROVISION_DIR>` with the your directory respectively.

  ```shell
  docker run -v <PATH_TO_KALEIDO_ROOT_DIR>:/root/Kaleido -p 80:8080 --device <YOUR_ENCLAVE_DIR> --device <YOUR_PROVISION_DIR> -ti cesslab/sgx-rust
  ```

  for example if the sgx driver is located in `/dev/sgx_enclave` and `/dev/sgx_provision` then run the following command

  ```shell
  docker run -v <PATH_TO_KALEIDO_ROOT_DIR>:/root/Kaleido -p 80:8080 --device /dev/sgx_enclave --device /dev/sgx_provision -ti cesslab/sgx-rust
  ```

* (PS):To run the container in simulation mode, For testing and development purpose

```bash
docker run --env SGX_MODE=SW -v <PATH_TO_KALEIDO_ROOT_DIR>:/root/Kaleido -p 80:8080 -ti cesslab/sgx-rust
```

After executing the above image running command, you will enter the container, please enter the kaleido directory, and then please open the sgx daemon

```shell
cd /root/Kaleido

LD_LIBRARY_PATH=/opt/intel/sgx-aesm-service/aesm/
/opt/intel/sgx-aesm-service/aesm/aesm_service
```

Add environment variables.When compiling by yourself, you need to apply for an account on the Intel website and subscribe to Development/Production Access. The address for application and subscription is:https://api.portal.trustedservices.intel.com/ 

```shell
##Log level
export RUST_LOG="debug"
export RUST_BACKTRACE=1
##Please fill in Primary key that you registered and subscribed from Intel in quotation marks
export IAS_API_KEY=""
##Please fill in SPID that you registered and subscribed from Intel in quotation marks
export IAS_SPID=""
##After Kaleido accepts the challenge from the CESS chain, it will start a period of verification. After the end, Kaleido completes the verification and returns the url of the result. This url is determined by the miner program, Here is an example.
export CESS_POST_CHAL_URL="http://127.0.0.1:10000/result"
```

build binaries:

```shell
cd /root/Kaleido
make
```

After waiting for the build to complete, run the binary in the background:

```shell
cd /root/Kaleido/bin
nohup ./app &
```

You can check if it works successfully

```shell
ps -ef |grep app
```



### Build and run image using docker scripts(Join CESS network ❌)

Please refer to the docker documentation for details:[Kaleido/docker/Docker Script Of Kaleido.md](https://github.com/CESSProject/Kaleido/tree/main/docker/Docker Script Of Kaleido.md)

### Download official image and run it with one click(Recommend ✔)(Join CESS network ✔)

Directly download the latest docker container pre-compiled by docker, you can easily start kaleido and join the CESS network

```shell
docker pull cesslab/sgx-rust:isgx
```

Run docker image

```shell
docker run -v /home/ubuntu/Kaleido/:/root/Kaleido -p 80:8080 --device /dev/isgx -v /:/sgx --name kaleido -tid cesslab/cess-kaleido:isgx
```



## Kaleido API Calls.

### `process_data`

**Description**: This function need to pass `file_path` to be processed. `block_size`determines the size of each chunk of the `data` while calculating PoDR2.increasing `segment_size` can reduce the size of file preprocessing results(`segment_size` must be able to divide block_size evenly). And the `callback_url` is the url where the computed PoDR2 result will be posted. 

**Request**

```bash
curl -H 'Content-Type: application/json' -X POST http://localhost:80/process_data -d '{"file_path":"<Path Of File To Be Processed>", "block_size":10,"segment_size":1, "callback_url":"<REPLACE_WITH_CALLBACK_URL>"}'
```

**Response**: The data will be posted back to the `callback_url` provided above with the following sample content.

```json
{
  "sigmas": [
    "36193ad3116bfd17e01ecb9ffcf0816d"
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



### `get_report`

**Description**: This method is used to obtain the remote attestation report obtained by the currently running Kaleido, and the result is called back to `callback_url`.

**Request**

```shell
curl -H 'Content-Type: application/json' -X POST http://localhost:80/get_report -d '{"callback_url":"<REPLACE_WITH_CALLBACK_URL>"}'
```

**Response**: The data will be posted back to the `callback_url` provided above with the following sample content.

```shell
"{\"id\":\"87097164558170109416329144617262300075\",\"timestamp\":\"2023-01-09T01:36:31.684273\",\"version\":4,\"epidPseudonym\":\"9B7Ac4onoHExqmjOIg0ldoYTF1jtI7wUlotfHyOqRTX36eZElWcxfxlEIeZy5RRMEeyEjMzl5q6H7fMUyTpDi3FJ9pIkskiHmnaXxSxMiR1Cx9czGmT6I+X5mrdDsprhY18ZqHITQ1eL5AeT2qVU0r2JpmekHzxdwgnE68GTb2o=\",\"advisoryURL\":\"https://security-center.intel.com\",\"advisoryIDs\":[\"INTEL-SA-00161\",\"INTEL-SA-00220\",\"INTEL-SA-00270\",\"INTEL-SA-00293\",\"INTEL-SA-00320\",\"INTEL-SA-00329\",\"INTEL-SA-00334\",\"INTEL-SA-00381\",\"INTEL-SA-00389\",\"INTEL-SA-00477\",\"INTEL-SA-00614\",\"INTEL-SA-00615\",\"INTEL-SA-00617\"],\"isvEnclaveQuoteStatus\":\"GROUP_OUT_OF_DATE\",\"platformInfoBlob\":\"1502006504000F0000131302040101070000000000000000000D00000C000000020000000000000B605F6DDD3CEA7DFBB7E93E996F1F03037A960A29436B47ADE4D9493BA3E5390FD960DBC8B6E9172402F3CF6025076D2CD93DF7BCD4E374CC0E6310199A707C81F3\",\"isvEnclaveQuoteBody\":\"AgABAGALAAAMAAwAAAAAANmMYLGtWKhiobXgZ0023bgAAAAAAAAAAAAAAAAAAAAABhMC//8CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAAKx8ZgJsS/SxVZ9oTuK+v1rjcGAE/VHnZ9fHpEzhQt87AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC9X3WOzjS60PChQQayLn72+ORCpfqAaLsPH0FLhvDT9kAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}|iuGIu8oJMDuwG+hGNDx3h/8zU1rg+X+KzRrR8bH02nZmqeImJXDeH2cPYYhrNp2nujyIjSQZRZRxzWwfzyM83vh+0LJiNwjyJlavzT8dxmc9oUGpKVDzIQBEoRcEy7edJG/diS+SJN/D884PrhnOk60JYJw3Wd/PLNhGkLURDQycy1yly5gff7vOufB/b0K5jmhgdsHMsBGtn14umV5XUSay0ZDbOg2Rryu1a7zsZAB914WM0KXgGpw+OXBlvbXD3Vkxm6xp6aYxR24RIK09si6QH+az3UbM5nmFpx6tJ2251rwCy+DulPuZPcD2bJ/S7yD1tw6v0u08+gML+0Jcrg==|MIIEoTCCAwmgAwIBAgIJANEHdl0yo7CWMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQDDCdJbnRlbCBTR1ggQXR0ZXN0YXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwHhcNMTYxMTIyMDkzNjU4WhcNMjYxMTIwMDkzNjU4WjB7MQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExFDASBgNVBAcMC1NhbnRhIENsYXJhMRowGAYDVQQKDBFJbnRlbCBDb3Jwb3JhdGlvbjEtMCsGA1UEAwwkSW50ZWwgU0dYIEF0dGVzdGF0aW9uIFJlcG9ydCBTaWduaW5nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqXot4OZuphR8nudFrAFiaGxxkgma/Es/BA+tbeCTUR106AL1ENcWA4FX3K+E9BBL0/7X5rj5nIgX/R/1ubhkKWw9gfqPG3KeAtIdcv/uTO1yXv50vqaPvE1CRChvzdS/ZEBqQ5oVvLTPZ3VEicQjlytKgN9cLnxbwtuvLUK7eyRPfJW/ksddOzP8VBBniolYnRCD2jrMRZ8nBM2ZWYwnXnwYeOAHV+W9tOhAImwRwKF/95yAsVwd21ryHMJBcGH70qLagZ7Ttyt++qO/6+KAXJuKwZqjRlEtSEz8gZQeFfVYgcwSfo96oSMAzVr7V0L6HSDLRnpb6xxmbPdqNol4tQIDAQABo4GkMIGhMB8GA1UdIwQYMBaAFHhDe3amfrzQr35CN+s1fDuHAVE8MA4GA1UdDwEB/wQEAwIGwDAMBgNVHRMBAf8EAjAAMGAGA1UdHwRZMFcwVaBToFGGT2h0dHA6Ly90cnVzdGVkc2VydmljZXMuaW50ZWwuY29tL2NvbnRlbnQvQ1JML1NHWC9BdHRlc3RhdGlvblJlcG9ydFNpZ25pbmdDQS5jcmwwDQYJKoZIhvcNAQELBQADggGBAGcIthtcK9IVRz4rRq+ZKE+7k50/OxUsmW8aavOzKb0iCx07YQ9rzi5nU73tME2yGRLzhSViFs/LpFa9lpQL6JL1aQwmDR74TxYGBAIi5f4I5TJoCCEqRHz91kpG6Uvyn2tLmnIdJbPE4vYvWLrtXXfFBSSPD4Afn7+3/XUggAlc7oCTizOfbbtOFlYA4g5KcYgS1J2ZAeMQqbUdZseZCcaZZZn65tdqee8UXZlDvx0+NdO0LR+5pFy+juM0wWbu59MvzcmTXbjsi7HY6zd53Yq5K244fwFHRQ8eOB0IWB+4PfM7FeAApZvlfqlKOlLcZL2uyVmzRkyR5yW72uo9mehX44CiPJ2fse9Y6eQtcfEhMPkmHXI01sN+KwPbpA39+xOsStjhP9N1Y1a2tQAVo+yVgLgV2Hws73Fc0o3wC78qPEA+v2aRs/Be3ZFDgDyghc/1fgU+7C+P6kbqd4poyb6IW8KCJbxfMJvkordNOgOUUxndPHEi/tb/U7uLjLOgPA==|0bff8986e1d2168ab9f12c90adbc3221fbcb0c6a624d9ee732ad51194b57fb830bdb03b03aad4d161e876a72f412684a283a0dd5ef179fc841b503d96f0c994800"
```



### `get_chal`

**Description**: This method receives an array of random challenges from the chain and returns an array of block challenges in `callback_url`.

**Request**

```shell
curl -H 'Content-Type: application/json' -X POST http://localhost:80/get_chal -d '{"n_blocks":512, "callback_url":"<REPLACE_WITH_CALLBACK_URL>", "proof_id":[1,3,0,255]}'
```

**Response**: The data will be posted back to the `callback_url` provided above with the following sample content.

```shell
{
  "challenge": {
    "chal_id": [
      1,
      3,
      0,
      255
    ],
    "time_out": 1673084189,
    "q_elements": [
      {
        "i": 2,
        "v": 310732984237164701
      },
      ...
    ]
  },
  "status": {
    "status_code": 100000,
    "status_msg": "ok"
  }
}
```

### `fill_random_file`

**Description**: This method is used to generate random files

**Request**

```shell
curl -H 'Content-Type: application/json' -X POST http://localhost:80/fill_random_file -d '{"file_path":"/sgx/root/sgx_test.txt","data_len":524288}'
```

**Response**: No result is returned, if the request is successful, the http status code is 200

### `message_signature`

**Description**: Sign the incoming result with the sgx authentication key and return it to `callback_url`.

**Request**

```shell
curl -H 'Content-Type: application/json' -X POST http://localhost:80/message_signature -d '{"msg":"hello world","callback_url":"<REPLACE_WITH_CALLBACK_URL>"}'
```

**Response**:

```shell
"6ee8cf1ef4450254ba89fc2c1f690abc9c58a0d10c75cb5732fde292d71b5bc444ac31d5897259e6b5f2ab51cf6f482358da63a41644666d4c6f39ec9e28bc5e00"
```

