BIN=task
SRC=task.c

CC=aarch64-linux-gnu-gcc
CFLAGS=-z execstack

$(BIN): $(SRC) ## build task
	docker build -f compile.Dockerfile -t compiler .
	docker run --rm -v $$(pwd):/tmp -w /tmp compiler $(CC) -o $@ $(CFLAGS) $^

clean: ## clear build artifacts
	rm -f -- task

public: clean $(BIN)  ## prepare public archive
	tar -czvf ../public/task.tar.gz $(BIN) $(SRC)

help:
	@egrep -h '\s##\s' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m  %-30s\033[0m %s\n", $$1, $$2}'
