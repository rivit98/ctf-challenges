FROM pwn.red/jail

COPY --from=ubuntu:24.04@sha256:c920ba4cfca05503764b785c16b76d43c83a6df8d1ab107e7e6610000d94315c / /srv

ARG flag_path

COPY task /srv/app/run
COPY ld-2.31.so libc-2.31.so /srv/app/
COPY ${flag_path} /srv/app/flag.txt

ENV JAIL_CONNS_PER_IP 3
