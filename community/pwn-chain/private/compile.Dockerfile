FROM ubuntu:20.04

RUN apt update && apt install -y gcc build-essential
RUN ldd --version

