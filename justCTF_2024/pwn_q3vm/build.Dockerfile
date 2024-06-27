FROM szymex73/ctf-build-tools

WORKDIR /tmp/task
COPY . .

WORKDIR /build/public/
RUN mkdir /tmp/q3vm
COPY ./public/ /tmp/q3vm
RUN tar -czvf q3vm.tar.gz -C /tmp/q3vm .

RUN mkdir -p /build/ && cd /tmp/task && python gen.py
RUN cd /build/ && zip -r /build/task.zip .
