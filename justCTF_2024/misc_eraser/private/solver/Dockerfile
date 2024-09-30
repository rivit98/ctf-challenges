FROM pwntools/pwntools:dev
ARG DEBIAN_FRONTEND=noninteractive

RUN sudo apt update && sudo apt install -y hashcash
COPY solve.py /
