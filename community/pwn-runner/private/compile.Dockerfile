FROM rivit98/nsjail:latest

RUN apt update && apt install -y libc6-dev-arm64-cross gcc-aarch64-linux-gnu
