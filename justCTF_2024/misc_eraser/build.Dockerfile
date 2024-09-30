FROM szymex73/ctf-build-tools

WORKDIR /tmp/task
COPY . .

WORKDIR /build/public/
RUN mkdir /tmp/eraser
COPY ./public/ /tmp/eraser
RUN tar -czvf eraser.tar.gz -C /tmp/eraser .

RUN mkdir -p /build/ && cd /tmp/task && python gen.py
RUN cd /build/ && zip -r /build/task.zip .
