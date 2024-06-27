FROM pwntools/pwntools:dev

COPY *.py /
COPY --from=ubuntu:23.10@sha256:008c4aa50da87ad7bc586a47787491f76c79c62cc5bdbee29121ee9e02c03f3e /lib/x86_64-linux-gnu/libc.so.6 /tmp/libc.so.6 
COPY ./q3vm /tmp/q3vm
WORKDIR /tmp

