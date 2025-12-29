BIN=task
SRC=task.c

CC=gcc
CFLAGS=-no-pie

$(BIN): $(SRC)
	$(CC) -o $@ $(CFLAGS) $^

clean: ## clear build artifacts
	rm -f -- task

public: clean $(BIN)  ## prepare public archive
	tar -czvf ../public/task.tar.gz $(BIN) $(SRC)
