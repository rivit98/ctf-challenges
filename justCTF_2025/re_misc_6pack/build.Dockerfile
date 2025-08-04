FROM szymex73/ctf-build-tools

WORKDIR /tmp/task
COPY . .

WORKDIR /build/public/
RUN mkdir /tmp/public
COPY ./public/6-pack /tmp/public
COPY ./public/Dockerfile /tmp/public
COPY ./public/dump.pcapng /tmp/public
RUN tar -czvf 6pack.tar.gz -C /tmp/public .

RUN mkdir -p /build/ && cd /tmp/task && python gen.py
RUN cd /build/ && zip -r /build/task.zip .
