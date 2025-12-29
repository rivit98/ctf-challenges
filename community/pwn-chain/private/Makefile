BIN=task
SRC=$(BIN).c

CC=gcc
CFLAGS=-fno-stack-protector -no-pie
DOCKER=docker run --rm -v $$(pwd):/work -w /work chain_compiler

$(BIN): $(SRC) ## build task
	docker build -f compile.Dockerfile -t chain_compiler .
	$(DOCKER) $(CC) $(CFLAGS) -o $@ $^
	$(DOCKER) ldd $@
	cp task task_patched
	patchelf --replace-needed libc.so.6 ./libc6_2.31-0ubuntu9.1_amd64.so task_patched
	patchelf --set-rpath . task_patched
	patchelf --set-interpreter ./ld-2.31.so task_patched
	ldd task_patched

clean: ## clear build artifacts
	rm -f -- task

public: clean $(BIN)  ## prepare public archive
	tar -czvf ../public/task.tar.gz $(BIN) $(SRC)

help:
	@egrep -h '\s##\s' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m  %-30s\033[0m %s\n", $$1, $$2}'


