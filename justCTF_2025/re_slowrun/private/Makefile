TASK := slowrun

.PHONY: build public solve clean

all: build public

build:
	docker build -t $(TASK)-builder -f compile.Dockerfile .
	docker run -u $$(id -u):$$(id -g) --rm -it -v $$PWD:/w -w /w $(TASK)-builder gcc -I . -O0 -s -mno-avx -fno-tree-vectorize -DNDEBUG -Wl,-z,stack-size=4194304 $(TASK).c BigInt/BigInt.c -lm -o $(TASK)

public:
	rm -rf ../public
	mkdir -p ../public
	cd ../public \
		&& ln -sf ../private/$(TASK) $(TASK) \
		&& ln -sf ../private/Dockerfile Dockerfile

test:
	docker run --rm -it -v $$PWD:/w -w /w python:3.13 python -B /w/test.py

clean:
	rm -rf --$(TASK)
