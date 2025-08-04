#!/usr/bin/env sh

NAME="solver-6-pack"
docker build -t ${NAME} -f ./solver/Dockerfile .
docker run --rm -it \
    --security-opt=no-new-privileges --cap-drop=ALL --user 1000:1000 \
    -v $PWD:/w -w /w \
    ${NAME} \
    /w/solver/solve.py
