CC=gcc
CFLAGS= -no-pie -Wl,-z,relro,-z,now

patcher: patcher.c
	$(CC) -o $@ $(CFLAGS) $^
	strip $@

test: patcher
	echo "CTFlearn{p4tching_4nd_p4tching}" | ./patcher 
