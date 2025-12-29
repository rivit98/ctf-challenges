BIN=task
SRC=$(BIN).c

CC=gcc
CFLAGS=-Wl,-z,relro -no-pie

$(BIN): $(SRC) ## build task
	$(CC) -o $@ $(CFLAGS) $^

clean: ## clear build artifacts
	rm -f -- task

public: clean $(BIN)  ## prepare public archive
	tar -czvf ../public/task.tar.gz $(BIN) $(SRC)

help:
	@egrep -h '\s##\s' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m  %-30s\033[0m %s\n", $$1, $$2}'
