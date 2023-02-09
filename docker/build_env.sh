#! /usr/bin/env bash
usage() {
cat << EOF
Usage: build CESS-SGX-PBC environment image (default, with no args) or base SGX-Rust environment (with -b option)
    -h   display this help message.
    -b   build SGX-Rust environment image
    -p   publish image
EOF
    exit 1;
}

PUBLISH=0
BASE_SGX=0
IAS_API_KEY=""
IAS_SPID=""

while getopts ":hpb" opt; do
    case ${opt} in
        h)
            usage
            ;;
        b)
            BASE_SGX=1
            ;;
        p)
            PUBLISH=1
            ;;
        ?)
            echo "Invalid Option: -$OPTARG" 1>&2
            exit 1
            ;;
    esac
done

if [ "$PUBLISH" -eq "1" ]; then
  echo "will publish image after build"
fi

DOCKER_FILE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

dockerfile_prefix="cess-sgxrust-pbc-env"
if [ "$BASE_SGX" -eq "1" ]; then
    dockerfile_prefix="cess-sgxrust-env"
fi

IMAGEID="cesslab/${dockerfile_prefix}:latest"

echo "building $IMAGEID image"
#docker build -f $DOCKER_FILE_DIR/env/${dockerfile_prefix}.Dockerfile -t $IMAGEID --build-arg https_proxy=172.16.2.137:7890 $DOCKER_FILE_DIR/env
docker build --build-arg IAS_API_KEY=$IAS_API_KEY --build-arg IAS_SPID=$IAS_SPID --build-arg -f $DOCKER_FILE_DIR/env/${dockerfile_prefix}.Dockerfile -t $IMAGEID $DOCKER_FILE_DIR/env
if [ "$?" -ne "0" ]; then
    echo "$IMAGEID build failed!"
    exit 1
fi
echo "build success"
if [ "$PUBLISH" -eq "1" ]; then
    echo "will publish $IMAGEID image"
    docker push $IMAGEID
fi
