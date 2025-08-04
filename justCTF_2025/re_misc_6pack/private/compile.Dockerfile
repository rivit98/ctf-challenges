FROM ubuntu:24.04
ARG DEBIAN_FRONTEND=noninteractive

COPY --from=golang:1.24.0 /usr/local/go/ /usr/local/go/

RUN apt-get update && apt-get install -y python3 python3-pip nasm wget gcc-mingw-w64-x86-64
RUN python3 -m pip install --break-system-packages lief pycryptodome


RUN mkdir -p /app
WORKDIR /app

RUN update-alternatives --install /bin/python python /bin/python3 1
RUN update-alternatives --install /bin/go go /usr/local/go/bin/go 1

RUN wget https://github.com/upx/upx/releases/download/v5.0.0/upx-5.0.0-amd64_linux.tar.xz
RUN tar -xvf upx-5.0.0-amd64_linux.tar.xz
RUN mv upx-5.0.0-amd64_linux/upx /usr/local/bin/upx
