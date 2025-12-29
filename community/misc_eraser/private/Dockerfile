FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends socat qemu-system-x86 hashcash \
    && rm -r /var/lib/apt/lists/*

RUN mkdir /home/ctf
WORKDIR /home/ctf

ARG flag_path

COPY ./vmlinuz64 .
COPY ./initramfs.cpio.gz .
COPY ./run.sh .
COPY ${flag_path} ./flag.txt

ENTRYPOINT socat -dd TCP4-LISTEN:5000,fork,reuseaddr,max-children=1,backlog=10 EXEC:"timeout 120 ./run.sh"


# build:
# docker build --build-arg flag_path=./flag.txt -t eraser .

# run
# docker run --privileged --rm -it -p 5000:5000 eraser

# connect
# nc localhost 5000