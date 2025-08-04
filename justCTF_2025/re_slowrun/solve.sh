#!/usr/bin/env bash

pushd private
docker run --rm -it \
    -v $PWD:/w -w /w \
    python:3.13 \
    python -B /w/solve.py 13337
popd
