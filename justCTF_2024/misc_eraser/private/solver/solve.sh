#!/usr/bin/env sh

if [ "$#" -le 1 ]; then
    echo "Use: <host> <port>"
    exit 1
fi

NAME="solver-misc-eraser"
docker build -t ${NAME} .

HOST=$1
PORT=$2
shift 2

docker run --rm -it \
    -u $(id -u):$(id -g) \
    --network=host \
    ${NAME} \
    /solve.py "HOST=$HOST" "PORT=$PORT" $@
