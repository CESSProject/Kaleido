#! /usr/bin/env bash

set -eux
SHOME_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
source $SHOME_DIR/utils.sh

usage() {
  echo "Usage:"
  echo "    $0 -h    display this help message."
  echo "    $0 [options]"
  echo "Options:"
  echo "     -p publish image"
  exit 1
}

PUBLISH=0

while getopts ":hp" opt; do
  case ${opt} in
  h)
    usage
    ;;
  p)
    PUBLISH=1
    ;;
  \?)
    echo "Invalid Option: -$OPTARG" 1>&2
    exit 1
    ;;
  esac
done

CTX_DIR="$(dirname $SHOME_DIR)"/bin
SGXDRIVER=$(cat $CTX_DIR/sgx_driver.txt | head -n 1)
if [ x"$SGXDRIVER" != x"dcap" ] && [ x"$SGXDRIVER" != x"isgx" ]; then
  log_err "Invalid sgx driver value: \"$SGXDRIVER\". Maybe the sgx_driver.txt file not found. Please perform build_bin.sh first."
  exit 1
fi

IMAGEID="cesslab/cess-kaleido:$SGXDRIVER"

cp -f $SHOME_DIR/runner/start.sh $CTX_DIR/

docker build --no-cache -t $IMAGEID -f $SHOME_DIR/runner/Dockerfile $CTX_DIR
if [ $? -ne "0" ]; then
  echo "$IMAGEID build failed!"
  exit 1
fi

if [ x"$SGXDRIVER" = x"dcap" ]; then
  image=($(docker images | grep cesslab/cess-kaleido | grep dcap))
  image=${image[2]}
  docker tag $image cesslab/cess-kaleido:latest
fi

echo "build success"
if [ "$PUBLISH" -eq "1" ]; then
  echo "will publish $IMAGEID image"
  docker push $IMAGEID
  if [ x"$SGXDRIVER" = x"dcap" ]; then
    docker push cesslab/cess-kaleido:latest
  fi
fi
