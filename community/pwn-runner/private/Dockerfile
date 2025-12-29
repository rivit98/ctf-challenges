FROM ubuntu:24.04@sha256:c920ba4cfca05503764b785c16b76d43c83a6df8d1ab107e7e6610000d94315c as builder
RUN apt update && apt install -y libc6-dev-arm64-cross qemu-user

FROM pwn.red/jail

COPY --from=builder / /srv

ARG flag_path

COPY run_task.sh /srv/app/run
COPY ${flag_path} /srv/app/flag.txt
COPY task /srv/app/

ENV JAIL_CONNS_PER_IP 3
