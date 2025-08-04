FROM szymex73/ctf-build-tools

WORKDIR /tmp/task
COPY . .

WORKDIR /build/public/
RUN mkdir /tmp/public
COPY ./public/Dockerfile /tmp/public
COPY ./public/flag.txt /tmp/public
COPY ./public/hook.sh /tmp/public
COPY ./public/run.sh /tmp/public
COPY ./public/tape /tmp/public
RUN tar -czvf tape.tar.gz -C /tmp/public .

RUN mkdir -p /build/ && cd /tmp/task && python gen.py
RUN cd /build/ && zip -r /build/task.zip .
