#!/bin/sh

/usr/bin/qemu-aarch64 -L /usr/aarch64-linux-gnu task 2>&1 | grep --line-buffered -v "qemu: "
