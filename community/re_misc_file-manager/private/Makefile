all: build public

.PHONY: build
build: main.cc
	docker build -t file-manager-builder -f compile.Dockerfile .
	docker run -u $$(id -u):$$(id -g) -t -v $$PWD:/w -w /w file-manager-builder \
		g++ main.cc -std=c++20 -O2 -fno-inline -s -o file-manager

.PHONY: public
public:
	rm -rf -- ../public/*
	mkdir -p ../public
	cp file-manager hook.sh Dockerfile ../public/
	echo "flag{this_is_a_fake_flag}" > ../public/flag.txt
	cd ../public && tar --remove-files -czf file-manager.tar.gz *

.PHONY: solve
solve:
	cd ./solver && ./solve.sh localhost 5000 DEBUG

.PHONY: run
run:
	cd .. && ./run.sh

.PHONY: clean
clean:
	rm -rf -- fs file-manager
