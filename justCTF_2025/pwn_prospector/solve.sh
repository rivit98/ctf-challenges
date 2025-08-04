#!/usr/bin/env bash

pushd private

docker run --rm -v $PWD:/w -w /w -it pwntools/pwntools:latest python3 solve.py EXE=./prospector REMOTE HOST=$1 PORT=$2 ${@:3}

popd