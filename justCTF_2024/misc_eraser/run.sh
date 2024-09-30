#!/usr/bin/env bash

PORT=${1-1337}
NAME="misc-eraser"

cd private
docker build -t ${NAME} -f Dockerfile .

docker rm -f ${NAME} || true
docker run -d \
    --restart=always \
    --name=${NAME} \
    -p $PORT:1337 \
    ${NAME}
