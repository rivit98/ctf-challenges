FROM ubuntu:24.04@sha256:c920ba4cfca05503764b785c16b76d43c83a6df8d1ab107e7e6610000d94315c as builder
RUN apt update && apt install -y dnsutils && rm -rf /var/lib/apt/lists/*

COPY resolv.conf /etc


FROM pwn.red/jail

COPY --from=builder / /srv
COPY hook.sh /jail/

ARG flag_path

COPY task /srv/app/run
COPY ${flag_path} /srv/app/flag.txt

ENV JAIL_CONNS_PER_IP 3
ENV JAIL_PIDS 10
