#!/usr/bin/env bash

docker build -t re_patcher .
docker run --rm -it re_patcher
