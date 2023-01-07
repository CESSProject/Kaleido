# Docker Script Of Kaleido

## Introduce

This is the docker script of kaleido, you can build a container containing kaleido according to this script.

`/docker/env`: The basic environment of the kaleido container.

`/docker/runner`: The construction and startup script of the kaleido container.

`/docker/build_env.sh`: Build the script of the docker environment. After use, the cess-sgxrust-pbc-env or cess-sgxrust-env image will be generated according to the parameters used. You can view the help through -h.

`/docker/build_bin.sh`: Used to compile the kaleido project, the obtained binary file `app` will be put into the generated cesslab/cess-kaleido image, and you can view the help by -h.

`/docker/build.sh`: The final cess-kaleido image will be built according to the type of driver, and the tag version will be assigned to the image. You can use -h to view the help.

`/docker/Cargo.config`: Due to Internet restrictions, Chinese users need to set a mirror source for rust.

`/docker/utils.sh`: Tool script, used to output script log.

## Prerequisites

* Linux System
* Docker



## Step

* First

```shell
./build_env.sh
```

Generate the cesslab/cess-sgxrust-pbc-env container through the cess-sgxrust-env:latest that has been released on the docker hub.



* Second

```
./build_bin.sh -s isgx -i <Your_IAS_SPID> -k <Your_IAS_API_KEY>
```

The parameter connected by -s means isgx or dcap based on driver install on the compiling machine. The parameter connected after -i indicates the `SPID` needed when compiling `Kaleido` (see Kaleido's README.MD for details). The parameter connected after -k indicates the `API_KEY` required when compiling Kaleido (see Kaleido's README.MD for details). At the same time, if you are a user in China, you can add a rust image to the container to improve the build by adding the -m command (for example: `./build_bin.sh -s isgx -i <Your_IAS_SPID> -k <Your_IAS_API_KEY> -m`).

* Third

```
./build.sh
```

Use this script to generate the final container `cesslab/cess-kaleido:<Your drive type>`.

