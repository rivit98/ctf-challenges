CC=gcc
CFLAGS = -O0

all: clean build public

build: patcher.c
	docker run --rm -u $$(id -u):$$(id -g) -t -v $$PWD:/w -w /w gcc:14 $(CC) $(CFLAGS) -DCTFLEARN -o patcher_ctflearn patcher.c
	docker run --rm -u $$(id -u):$$(id -g) -t -v $$PWD:/w -w /w gcc:14 strip patcher_ctflearn

	docker run --rm -u $$(id -u):$$(id -g) -t -v $$PWD:/w -w /w gcc:14 $(CC) $(CFLAGS) -DCTFGUIDE -o patcher_ctfguide patcher.c
	docker run --rm -u $$(id -u):$$(id -g) -t -v $$PWD:/w -w /w gcc:14 strip patcher_ctfguide

clean:

public: build
	rm -rf -- ../public/*
	mkdir -p ../public/ctfguide
	cp Dockerfile ../public/ctfguide
	cp run.sh ../public/ctfguide
	cp -r ../public/ctfguide ../public/ctflearn

	cp patcher_ctflearn ../public/ctflearn/patcher
	cp patcher_ctfguide ../public/ctfguide/patcher

	cd ../public/ctfguide && tar czf patcher.tar.gz --remove-files -- *
	cd ../public/ctflearn && tar czf patcher.tar.gz --remove-files -- *

solve:
	cat flag_ctflearn.txt | docker run --rm -u $$(id -u):$$(id -g) -i -v $$PWD:/w -w /w gcc:14 ./patcher_ctflearn | grep "Correct" && echo "ok" || echo "fail"
	cat flag_ctfguide.txt | docker run --rm -u $$(id -u):$$(id -g) -i -v $$PWD:/w -w /w gcc:14 ./patcher_ctfguide | grep "Correct" && echo "ok" || echo "fail"

.PHONY: build solve public 
