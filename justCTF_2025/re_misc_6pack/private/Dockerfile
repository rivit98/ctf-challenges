FROM ubuntu:24.04
ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get -y install netbase net-tools \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir /app
COPY 6-pack /app/

CMD [ "/app/6-pack" ]
