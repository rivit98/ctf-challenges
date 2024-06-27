FROM ubuntu:23.10@sha256:008c4aa50da87ad7bc586a47787491f76c79c62cc5bdbee29121ee9e02c03f3e AS builder
ARG DEBIAN_FRONTEND=noninteractive
RUN apt update && apt -y install gcc

WORKDIR /tmp
COPY ./runner.c .

# built using Dockerfile.q3vm
COPY ./q3vm . 
RUN gcc runner.c -O2 -s -o runner


FROM ubuntu:23.10@sha256:008c4aa50da87ad7bc586a47787491f76c79c62cc5bdbee29121ee9e02c03f3e
ARG DEBIAN_FRONTEND=noninteractive

##################################### NSJAIL SETUP #####################################
RUN apt update && apt install -y curl wget xz-utils sudo coreutils adduser

# Install Nix package manager
# (We could do it with sh curl, but we better validate the .tar.xz with a hash)
#RUN bash -c "sh <(curl -L https://nixos.org/nix/install) --no-daemon"
RUN wget https://releases.nixos.org/nix/nix-2.15.1/nix-2.15.1-x86_64-linux.tar.xz && \
    tar -xvf nix-2.15.1-x86_64-linux.tar.xz && \
    echo '9345c1485dadb1cb66ed54aa97c692ab38f7ead2d609230564e6673490f30365 nix-2.15.1-x86_64-linux.tar.xz' | sha256sum -c

RUN adduser --disabled-password --gecos '' nix && \
    adduser nix sudo && \
    echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

USER nix
ENV USER=nix
RUN cd nix-2.15.1-x86_64-linux && \
    ./install --no-daemon

# Install Nsjail using Nix
RUN . /home/nix/.nix-profile/etc/profile.d/nix.sh && \
    nix-env -iA nixpkgs.nsjail
COPY ./nsjail.cfg /nsjail.cfg

# Bring back root user
USER root
ENV USER=root

# Eventually, disable sudo
RUN sed -i '$ d' /etc/sudoers 
RUN adduser --gecos '' jailed
############################# END OF NSJAIL SETUP #####################################

# Challenge data/files
WORKDIR /jailed

COPY ./flag.txt /flag.txt
COPY ./run.sh .
COPY --from=builder /tmp/q3vm .
COPY --from=builder /tmp/runner .

RUN chown -R jailed:jailed ./*
RUN chmod +x ./*

CMD ["/home/nix/.nix-profile/bin/nsjail", "--config", "/nsjail.cfg"]
