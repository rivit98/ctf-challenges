#!/usr/bin/env bash

pushd private

while :; do
    out=`docker run --rm -v $PWD:/w -w /w -it pwntools/pwntools:latest python3 solve.py EXE=./tape REMOTE HOST=$1 PORT=$2 ${@:3} | tee /dev/tty`

    if [[ $out == *"justCTF{"* ]]; then
        break
    fi

    echo "not flag yet, repeating..."
    echo -e "\n\n\n"

done

echo "found flag: $out"

popd
