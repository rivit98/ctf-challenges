TASK := shellcode_printer

.PHONY: build public solve clean

all: build public

build:
	docker build -t $(TASK)-builder -f compile.Dockerfile .
	docker run -u $$(id -u):$$(id -g) --rm -it -v $$PWD:/w -w /w $(TASK)-builder gcc -Wall $(TASK).c -o $(TASK) -s

public:
	rm -rf ../public
	mkdir -p ../public
	cd ../public \
		&& ln -sf ../private/$(TASK) $(TASK) \
		&& ln -sf ../private/Dockerfile Dockerfile \
		&& echo "flag{flag}" > ./flag.txt

solve:
	./solver/solve.sh

clean:
	rm -rf --$(TASK)
