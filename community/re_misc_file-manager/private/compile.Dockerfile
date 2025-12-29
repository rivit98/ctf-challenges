FROM debian:bookworm-slim@sha256:d365f4920711a9074c4bcd178e8f457ee59250426441ab2a5f8106ed8fe948eb
ARG DEBIAN_FRONTEND=noninteractive

RUN apt update \
    && apt install -y g++
