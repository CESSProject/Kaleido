#! /usr/bin/env bash

usage() {
    echo "Usage:"
	echo "    $0 -h    display this help message."
	echo "    $0 [options]"
    echo "Options:"
    echo "     -p publish image"
	exit 1;
}

PUBLISH=0

while getopts ":hp" opt; do
    case ${opt} in
        h )
			usage
            ;;
        p )
            PUBLISH=1
            ;;
        \? )
            echo "Invalid Option: -$OPTARG" 1>&2
            exit 1
            ;;
    esac
done

DOCKER_FILE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
CTX_DIR="`dirname $DOCKER_FILE_DIR`"
IMAGEID="cesslab/cess-kaleido:latest"

docker build -t $IMAGEID -f $DOCKER_FILE_DIR/runner/Dockerfile $CTX_DIR
if [ $? -ne "0" ]; then
    echo "$IMAGEID build failed!"
    exit 1
fi

echo "build success"
if [ "$PUBLISH" -eq "1" ]; then
    echo "will publish $IMAGEID image"
    docker push $IMAGEID
fi
