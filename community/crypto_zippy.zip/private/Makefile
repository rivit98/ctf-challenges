all: clean build public

build: 
	mkdir -p build
	docker run --rm -u $$(id -u):$$(id -g) -t -v $$PWD:/w -w /w python:3.12-slim python gen.py flag.txt build
	ls -lh build
	cd build && zip -P $(shell cat /dev/urandom | tr -dc '[:alpha:]' | fold -w 30 | head -n 1 | tee password.txt) -r ../zippy.zip *

clean:
	rm -rf build

public:
	rm -rf -- ../public
	mkdir -p ../public
	cp zippy.zip ../public

solve:
	docker run --rm -u $$(id -u):$$(id -g) -t -v $$PWD:/w -w /w/solve rust cargo run --release -- ../zippy.zip


.PHONY: build solve public clean
