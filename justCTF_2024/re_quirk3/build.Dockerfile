FROM szymex73/ctf-build-tools

WORKDIR /tmp/task
COPY . .

WORKDIR /build/public/
RUN mkdir /tmp/quirk3
COPY ./public/ /tmp/quirk3
RUN tar -czvf quirk3.tar.gz -C /tmp/quirk3 .

RUN mkdir -p /build/ && cd /tmp/task && python gen.py
RUN cd /build/ && zip -r /build/task.zip .
