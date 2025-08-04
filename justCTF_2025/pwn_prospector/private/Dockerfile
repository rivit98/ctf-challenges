FROM ubuntu:25.04@sha256:95a416ad2446813278ec13b7efdeb551190c94e12028707dd7525632d3cec0d1 as base

FROM pwn.red/jail

COPY --from=base / /srv
COPY prospector /srv/app/prospector
COPY run.sh /srv/app/run
COPY flag.txt /srv/app/flag.txt

ENV JAIL_CONNS_PER_IP=3
ENV JAIL_TIME=600
