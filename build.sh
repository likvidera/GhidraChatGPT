#!/bin/bash

set -e

VERSION=10.2.3
GID=$(id -g)
DOCKER_GHIDRA_IMG="ghidra-chatgpt:$VERSION"
DOCKER_BUILD=0
FORCE_BUILD=0
DEV_BUILD=0
GHIDRA_PATH=${GHIDRA_INSTALL_DIR}
GHIDRA_MNT_DIR=/ghidra

SCRIPT_DIR=$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
cd "$SCRIPT_DIR"

function docker_build() {
    echo "[+] Building the GhidraChatGPT Plugin" >&2

    if [ "$(docker images -q "$DOCKER_GHIDRA_IMG" 2> /dev/null)" == "" ] || [ $FORCE_BUILD -ne 0 ]; then
        docker build \
        --build-arg UID=$UID \
        --build-arg GID=$GID \
        -t "$DOCKER_GHIDRA_IMG" \
        .
    fi

    docker run -t --rm \
    --user $UID:$GID \
    --mount type=bind,source="$GHIDRA_PATH",target="$GHIDRA_MNT_DIR" \
    --entrypoint /entry "$DOCKER_GHIDRA_IMG"
}

function build() {
    echo "[+] Building the GhidraChatGPT Plugin" >&2

    export GHIDRA_INSTALL_DIR="$GHIDRA_PATH"
    pushd ghidrachatgpt > /dev/null 2>&1
    gradle
    
    APPNAME=$(ls dist/*.zip | xargs basename)
    cp dist/*.zip "$GHIDRA_PATH/Extensions/Ghidra"
    echo "[+] Built $APPNAME and copied it to $GHIDRA_PATH/Extensions/Ghidra/$APPNAME"
    popd > /dev/null 2>&1
}

function usage() {
    echo "Usage: $0 [OPTION...] [CMD]" >&2
    echo "  -p PATH        PATH to local Ghidra installation" >&2
    echo "  -d             Build with Docker" >&2
    echo "  -f             Force rebuild of the Docker image" >&2
    echo "  -h             Show this help" >&2
}

while getopts "p:dfh" opt; do
    case "$opt" in
        p)
            GHIDRA_PATH=$(realpath ${OPTARG})
            ;;
        d)
            DOCKER_BUILD=1
            ;;
        f)
            FORCE_BUILD=1
            ;;
        h)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $opt" >&2
            usage
            exit 1
            ;;
    esac
done
shift $((OPTIND-1))

if [ -z $GHIDRA_PATH ] || [ ! -d $GHIDRA_PATH ] ; then
    echo "GHIDRA_PATH is not configured or is not a directory"
    exit 1
fi

if [ $DOCKER_BUILD -ne 0 ] ; then
    docker_build
else   
    build
fi

exit 0
