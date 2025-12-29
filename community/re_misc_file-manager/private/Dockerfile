FROM debian:bookworm-slim@sha256:d365f4920711a9074c4bcd178e8f457ee59250426441ab2a5f8106ed8fe948eb AS base

ARG DEBIAN_FRONTEND=noninteractive

RUN apt update \
    && apt install -y zip \
    && rm -rf /var/lib/apt/lists/*

FROM pwn.red/jail

COPY --from=base / /srv

ARG flag_path

COPY file-manager /srv/app/run
COPY ${flag_path} /srv/app/flag.txt
COPY hook.sh /jail/

ENV JAIL_CONNS_PER_IP=3
ENV JAIL_TIME=300

# build:
# docker build --build-arg flag_path=./flag.txt -t file-manager .

# run
# docker run --privileged --rm -it -p 5000:5000 file-manager

# connect
# nc localhost 5000
