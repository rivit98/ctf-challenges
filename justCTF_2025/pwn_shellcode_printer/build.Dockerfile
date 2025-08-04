FROM szymex73/ctf-build-tools

WORKDIR /tmp/task
COPY . .

WORKDIR /build/public/
RUN mkdir /tmp/public
COPY ./public/Dockerfile /tmp/public
COPY ./public/flag.txt /tmp/public
COPY ./public/shellcode_printer /tmp/public
RUN tar -czvf shellcode_printer.tar.gz -C /tmp/public .

RUN mkdir -p /build/ && cd /tmp/task && python gen.py
RUN cd /build/ && zip -r /build/task.zip .
