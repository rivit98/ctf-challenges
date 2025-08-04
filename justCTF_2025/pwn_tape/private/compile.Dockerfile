FROM ubuntu:25.04@sha256:79efa276fdefa2ee3911db29b0608f8c0561c347ec3f4d4139980d43b168d991
ARG DEBIAN_FRONTEND=noninteractive

RUN dpkg --add-architecture i386 \
    && apt-get update \
    && apt-get install -y \
        libc6:i386=2.41-6ubuntu1 \
        libc6-dbg:i386=2.41-6ubuntu1 \
        elfutils \
        gcc:i386 \
        vim \
        patchelf \
    && rm -rf /var/lib/apt/lists/*

