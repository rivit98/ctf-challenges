.PHONY: runner q3vm-build public solve run


runner: runner.c
	gcc runner.c -Wall -Wextra -Wpedantic -O2 -s -o runner


q3vm-build:
	docker build -f Dockerfile.q3vm -t q3vm-build .
	docker run -u $(shell id -u):$(shell id -g) -v $$PWD:/w q3vm-build cp ./q3vm /w
	# docker run -u $(shell id -u):$(shell id -g) -v $$PWD:/w q3vm-build cp /lib/x86_64-linux-gnu/libc.so.6 /w
	# docker run -u $(shell id -u):$(shell id -g) -v $$PWD:/w q3vm-build cp /lib64/ld-linux-x86-64.so.2 /w


public:
	mkdir -p ../public
	cp runner.c ../public
	cp Dockerfile ../public
	cp Dockerfile.q3vm ../public
	cp run.sh ../public
	cp q3vm ../public
	cp nsjail.cfg ../public
	echo "REDACTED" > ../public/flag.txt
	cp flag.txt ../flag.txt


solve:
	cd ./solver && ./solve.sh localhost 1337


run:
	cd .. && ./run.sh
