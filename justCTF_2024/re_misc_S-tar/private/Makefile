all: build public

.PHONY: build
build: main.cc
	docker build -t star-builder -f compile.Dockerfile .
	docker run -u $$(id -u):$$(id -g) -t -v $$PWD:/w -w /w star-builder \
		g++ main.cc -std=c++23 -fno-elide-constructors -O2 -fno-inline -s -o star

.PHONY: public
public:
	mkdir -p ../public
	cp flag.txt ../flag.txt
	cp star ../public/star

.PHONY: solve
solve:
	cd ./solver && ./solve.sh localhost 1337

.PHONY: run
run:
	cd .. && ./run.sh

.PHONY: clean
clean:
	rm -rf -- fs star
