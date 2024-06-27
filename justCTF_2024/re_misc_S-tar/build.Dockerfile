FROM szymex73/ctf-build-tools

WORKDIR /tmp/task
COPY . .

WORKDIR /build/public/
RUN mkdir /tmp/star
COPY ./public/star /tmp/star
RUN tar -czvf star.tar.gz -C /tmp/star .

RUN mkdir -p /build/ && cd /tmp/task && python gen.py
RUN cd /build/ && zip -r /build/task.zip .
