CC=lcc
LINK=q3asm
CFLAGS = -S -Wf-target=bytecode -Wf-g

all: clean build public

build: g_main.c g_syscalls.asm
	mkdir -p build
	docker build -t re_quack3-builder -f Dockerfile.q3vm .

	docker run --rm -u $$(id -u):$$(id -g) -t -v $$PWD:/w -w /w re_quack3-builder $(CC) $(CFLAGS) -DCTFGUIDE -o build/g_main.asm g_main.c
	docker run --rm -u $$(id -u):$$(id -g) -t -v $$PWD:/w -w /w re_quack3-builder $(LINK) -f challenge -o challenge-ctfguide.qvm

	docker run --rm -u $$(id -u):$$(id -g) -t -v $$PWD:/w -w /w re_quack3-builder $(CC) $(CFLAGS) -DCTFLEARN -o build/g_main.asm g_main.c
	docker run --rm -u $$(id -u):$$(id -g) -t -v $$PWD:/w -w /w re_quack3-builder $(LINK) -f challenge -o challenge-ctflearn.qvm

	docker run --rm -u $$(id -u):$$(id -g) -t -v $$PWD:/w -w /w re_quack3-builder cp /q3vm/q3vm /w

	ls -lh build

clean:
	rm -rf build

public: build
	rm -rf -- ../public/*
	mkdir -p ../public/ctfguide
	cp q3vm ../public/ctfguide
	cp Dockerfile ../public/ctfguide
	cp run.sh ../public/ctfguide
	cp -r ../public/ctfguide ../public/ctflearn

	cp challenge-ctfguide.qvm ../public/ctfguide/challenge.q3vm
	cp challenge-ctflearn.qvm ../public/ctflearn/challenge.q3vm

	cd ../public/ctfguide && tar czf quack3.tar.gz --remove-files -- *
	cd ../public/ctflearn && tar czf quack3.tar.gz --remove-files -- *

solve:
	mkdir -p build
	docker build -t re_quack3-builder -f Dockerfile.q3vm .

	docker run --rm -u $$(id -u):$$(id -g) -t -v $$PWD:/w -w /w re_quack3-builder g++ -std=c++20 -I . -DCTFGUIDE solve/solve.cpp -o build/solve
	docker run --rm -u $$(id -u):$$(id -g) -t -v $$PWD:/w -w /w re_quack3-builder /w/build/solve

	docker run --rm -u $$(id -u):$$(id -g) -t -v $$PWD:/w -w /w re_quack3-builder g++ -std=c++20 -I . -DCTFLEARN solve/solve.cpp -o build/solve
	docker run --rm -u $$(id -u):$$(id -g) -t -v $$PWD:/w -w /w re_quack3-builder /w/build/solve

.PHONY: build solve public 
