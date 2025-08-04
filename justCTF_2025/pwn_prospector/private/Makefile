TASK := prospector

.PHONY: build public solve clean

all: build public

build:
	docker build -t $(TASK)-builder -f compile.Dockerfile .
	docker run -u $$(id -u):$$(id -g) --rm -it -v $$PWD:/w -w /w $(TASK)-builder gcc -nostdlib -Wall $(TASK).c libc.c -o $(TASK) -s

public:
	rm -rf ../public
	mkdir -p ../public
	cd ../public \
		&& ln -sf ../private/$(TASK) $(TASK) \
		&& ln -sf ../private/Dockerfile Dockerfile \
		&& ln -sf ../private/run.sh run.sh \
		&& echo "flag{flag}" > ./flag.txt

solve:
	./solver/solve.sh

clean:
	rm -rf --$(TASK)
