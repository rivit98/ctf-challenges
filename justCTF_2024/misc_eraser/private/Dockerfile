FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends socat qemu-system-x86 hashcash \
    && rm -r /var/lib/apt/lists/*

RUN mkdir /home/ctf
WORKDIR /home/ctf

COPY ./vmlinuz64 .
COPY ./initramfs.cpio.gz .
COPY ./run.sh .
COPY ./flag.txt .

ENTRYPOINT socat -dd TCP4-LISTEN:1337,fork,reuseaddr EXEC:"timeout 120 ./run.sh"
