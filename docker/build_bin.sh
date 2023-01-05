#! /usr/bin/env bash

SHOME_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
BUILD_DIR="$(dirname $SHOME_DIR)"
DIST_FILE="$BUILD_DIR/bin/app"
source $SHOME_DIR/utils.sh

usage() {
  echo "Usage:"
  echo "    $0 -h               Display this help message."
  echo "    $0 [options]"
  echo "Options:"
  echo "     -s specify the SGX driver, dcap or isgx, dcap for default"
  echo "     -c [dir] use cache directory"
  echo "     -r rebuild, will do clean and build"
  echo "     -m use Chinese cargo mirror"
  exit 1
}

MIRROR=0
CACHEDIR=""
REBUILD=0
SGXDRIVER="dcap"
IASAPIKEY=""
IASSPID=""

while getopts ":hmrc:s:k:a" opt; do
  case ${opt} in
  h)
    usage
    ;;
  m)
    MIRROR=1
    ;;
  r)
    REBUILD=1
    ;;
  c)
    CACHEDIR=$OPTARG
    ;;
  s)
    SGXDRIVER=$OPTARG
    ;;
  k)
    IASAPIKEY=$OPTARG
    echo $IASAPIKEY
    ;;
  a)
    IASSPID=$OPTARG
    echo $IASSPID
    ;;
  \?)
    echo "Invalid options: -$OPTARG" 1>&2
    exit 1
    ;;
  esac
done

log_info "Using cargo cache dir: $CACHEDIR"
if [ ! -d $CACHEDIR ]; then
  log_err "directory $CACHEDIR doesn't exist!"
  exit 1
fi

if [ -z $CACHEDIR ]; then
  CACHEDIR="${BUILD_DIR}/docker/.cargo_cache"
  log_info "Using default cargo cache dir: $CACHEDIR"
  mkdir -p $CACHEDIR
fi

function build_bin {
  log_info "Using build dir: $BUILD_DIR"

  local -r build_img="cesslab/cess-sgxrust-pbc-env:latest"
  log_success "Preparing docker build image, running docker pull ${build_img}"
  docker pull ${build_img}
  if [ $? -ne 0 ]; then
    echo "Failed to pull docker image."
    exit 1
  fi

  if [ $MIRROR -eq "1" ]; then
    echo "Config mirror..."
    mkdir -p $BUILD_DIR/.cargo
    cp $BUILD_DIR/docker/Cargo.config $BUILD_DIR/.cargo/config
  else
    rm -f $BUILD_DIR/.cargo/config
  fi

  SGX_OPTS="--device /dev/sgx/enclave --device /dev/sgx/provision"
  if [ x"$SGXDRIVER" = x"isgx" ]; then
    SGX_OPTS="--device /dev/isgx"
  elif [ x"$SGXDRIVER" != x"dcap" ]; then
    log_err "invalid sgx driver option: $SGXDRIVER, use default dcap"
    SGXDRIVER="dcap"
  fi
  VOL_OPTS="-v $BUILD_DIR:/opt/kaleido -v $CACHEDIR:/opt/cargo_cache"

  log_info "volume opts: $VOL_OPTS"
  log_info "SGX opts: $SGX_OPTS"

  CIDFILE=$(mktemp)
  rm $CIDFILE
  CMD=""
  if [ $REBUILD -eq "1" ]; then
    CMD="make clean; "
  fi
  CMD="$CMD make"

  log_info "Building command: $CMD"
  docker run --network host --workdir /opt/kaleido --cidfile $CIDFILE -it --env CARGO_HOME=/opt/cargo_cache $VOL_OPTS $SGX_OPTS $build_img /bin/bash -c "$CMD"
  CID=$(cat $CIDFILE)
  log_info "Cleanup temp container $CID"
  docker rm $CID
  log_info "Build done, checking results"

  if [ ! -f $DIST_FILE ]; then
    log_err "Build failed, $DIST_FILE does not exist"
    exit 1
  else
    cat >$BUILD_DIR/bin/sgx_driver.txt <<EOF
$SGXDRIVER
EOF
    log_success "$DIST_FILE exists - passed"
  fi
  log_info "kaleido built at: $DIST_FILE"
}

#set -eux
build_bin
