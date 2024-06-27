#!/usr/bin/env sh

if [ "$#" -le 1 ]; then
    echo "Use: <host> <port>"
    exit 1
fi

cp ../q3vm ./q3vm

NAME="solver-pwn-q3vm"
docker build -t ${NAME} .

while :; do
    docker run --rm -it \
        --security-opt=no-new-privileges --cap-drop=ALL --user 1000:1000 \
        --network=host \
        ${NAME} \
        /solve.py EXE=/q3vm "HOST=$1" "PORT=$2" REMOTE $@

    if [ $? -eq 0 ]; then
        break
    fi
done
