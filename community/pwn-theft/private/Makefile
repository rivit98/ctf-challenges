BIN=task
SRC=$(BIN).c

CC=gcc
CFLAGS=-Wl,-z,now -Wl,-z,relro -g

$(BIN): $(SRC) ## build task
	docker build -f compile.Dockerfile -t theft_compiler .
	docker run --rm -v $$(pwd):/work -w /work theft_compiler $(CC) $(CFLAGS) -o $@ $^
	patchelf --replace-needed libc.so.6 ./libc-2.31.so task
	patchelf --set-interpreter ./ld-2.31.so task
	docker run --rm -v $$(pwd):/work -w /work theft_compiler ldd $@
 

clean: ## clear build artifacts
	rm -f -- task

public: clean $(BIN)  ## prepare public archive
	tar -czvf ../public/task.tar.gz $(BIN) $(SRC) ./ld-2.31.so ./libc-2.31.so

help:
	@egrep -h '\s##\s' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m  %-30s\033[0m %s\n", $$1, $$2}'
