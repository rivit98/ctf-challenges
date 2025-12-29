BIN=task
SRC=task.c

CC=gcc
CFLAGS=-fno-stack-protector -m32 -no-pie

$(BIN): $(SRC) ## build task
	$(CC) -o $@ $(CFLAGS) $^
	patchelf --set-interpreter ld-linux.so.2  $@
	patchelf --set-rpath '.' $@
	patchelf --replace-needed libc.so.6 ./libc.so.6 $@

clean: ## clear build artifacts
	rm -f -- task

public: clean $(BIN)  ## prepare public archive
	tar -czvf ../public/task.tar.gz $(BIN) $(SRC)

help:
	@egrep -h '\s##\s' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m  %-30s\033[0m %s\n", $$1, $$2}'
