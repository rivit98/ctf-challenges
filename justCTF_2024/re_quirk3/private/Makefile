CC=lcc
LINK=q3asm
CFLAGS = -S -Wf-target=bytecode -Wf-g

all: clean build public

build: g_main.c g_syscalls.asm
	mkdir -p build
	docker build -t re_quirk3-builder -f Dockerfile.q3vm .

	docker run --rm -u $$(id -u):$$(id -g) -t -v $$PWD:/w -w /w re_quirk3-builder $(CC) $(CFLAGS) -o build/g_main.asm g_main.c
	docker run --rm -u $$(id -u):$$(id -g) -t -v $$PWD:/w -w /w re_quirk3-builder $(LINK) -f challenge -o challenge.qvm

	docker run --rm -u $$(id -u):$$(id -g) -t -v $$PWD:/w -w /w re_quirk3-builder cp /q3vm/q3vm /w

	ls -lh build

clean:
	rm -rf build

public: build
	rm -rf -- ../public/*
	cp q3vm ../public
	cp Dockerfile ../public
	cp run.sh ../public
	cp challenge.qvm ../public/

	cp flag.txt ../flag.txt

solve:
	mkdir -p build
	docker build -t re_quirk3-builder -f Dockerfile.q3vm .

	docker run --rm -u $$(id -u):$$(id -g) -t -v $$PWD:/w -w /w re_quirk3-builder g++ -std=c++20 -I . solve/solve.cpp -o build/solve
	docker run --rm -u $$(id -u):$$(id -g) -t -v $$PWD:/w -w /w re_quirk3-builder /w/build/solve


run: build
	docker build -t re_quirk3-runner -f Dockerfile .
	docker run --rm -u $$(id -u):$$(id -g) -it -v $$PWD:/w -w /w re_quirk3-builder ./q3vm ./challenge.qvm


.PHONY: build solve public run clean
