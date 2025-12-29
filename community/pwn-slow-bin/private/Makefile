BIN=task
SRC=$(BIN).c

CC=zig cc
CFLAGS=-target native-native-gnu.2.30 -no-pie -fstack-protector-all -Wl,-rpath=. -Wl,--dynamic-linker=./ld-2.30.so -Wl,-z,now -Wl,-z,relro -g

$(BIN): $(SRC) ## build task
	$(CC) $(CFLAGS) -o $@ $^
	patchelf --replace-needed libpthread.so.0 libc.so.6 task # remove pthread lol
	patchelf --replace-needed libc.so.6 libc-2.30-no-tcache.so task
	ldd $@

clean: ## clear build artifacts
	rm -f -- task

public: clean $(BIN)  ## prepare public archive
	tar -czvf ../public/task.tar.gz $(BIN) $(SRC) ./ld-2.30.so ./libc-2.30-no-tcache.so

help:
	@egrep -h '\s##\s' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m  %-30s\033[0m %s\n", $$1, $$2}'
