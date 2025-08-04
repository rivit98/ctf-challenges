#!/usr/bin/env bash

PORT=${1-1337}

NAME="pwn-tape"

cd private
docker build -t ${NAME} -f Dockerfile .

docker rm -f ${NAME} || true
docker run -d \
    --restart=always \
    --name=${NAME} \
    --privileged \
    -p $PORT:5000 \
    ${NAME}