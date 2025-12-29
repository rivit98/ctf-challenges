BIN=task
SRC=task.c

CC=gcc
CFLAGS=

$(BIN): $(SRC)
	$(CC) -o $@ $(CFLAGS) $^

clean:
	rm -f -- task

public: clean $(BIN)
	tar -czvf ../public/task.tar.gz $(BIN) $(SRC)

