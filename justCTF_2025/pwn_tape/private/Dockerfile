FROM ubuntu:25.04@sha256:79efa276fdefa2ee3911db29b0608f8c0561c347ec3f4d4139980d43b168d991 as base
ARG DEBIAN_FRONTEND=noninteractive

RUN dpkg --add-architecture i386 \
    && apt-get update \
    && apt-get install -y \
        libc6:i386=2.41-6ubuntu1 \
    && rm -rf /var/lib/apt/lists/*

FROM pwn.red/jail

COPY --from=base / /srv
COPY tape /srv/app/tape
COPY run.sh /srv/app/run
COPY flag.txt /srv/app/flag.txt
COPY hook.sh /jail/

ENV JAIL_CONNS_PER_IP=3
