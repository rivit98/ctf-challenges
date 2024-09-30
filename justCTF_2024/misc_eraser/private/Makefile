SHELL = bash

.PHONY: build eraser initramfs test public solve run clean

all: build public

build: eraser initramfs

eraser: main.c 
	docker build -t misc-eraser-builder -f compile.Dockerfile .
	docker run -u $$(id -u):$$(id -g) -t -v $$PWD:/w -w /w misc-eraser-builder \
		gcc main.c -s -o eraser
	docker run -u $$(id -u):$$(id -g) -t -v $$PWD:/w -w /w misc-eraser-builder \
		strip eraser

initramfs: eraser
	chmod +x ./eraser
	sudo cp -p eraser ./initramfs/usr/bin
	sudo chown root:root ./initramfs/usr/bin/eraser
	sudo chmod u+s ./initramfs/usr/bin/eraser

initramfs-unpack:
	mkdir initramfs
	cd initramfs && zcat ../corepure64.gz | fakeroot -s ../initramfs.fakeroot cpio -i
	du -hs initramfs

initramfs-pack:
	cd initramfs && find -print0 | xargs -0 sudo touch || true
	cd initramfs && find | fakeroot -i ../initramfs.fakeroot cpio -o -H newc | gzip -c > ../initramfs.cpio.gz
	du -hs initramfs.cpio.gz

test: eraser
	docker build -t misc-eraser-test -f test.Dockerfile .
	docker run -w /app misc-eraser-test python /app/test.py

public:
	rm -rf ../public
	mkdir -p ../public
	cp flag.txt ../flag.txt
	echo "justCTF{flag}" >> ../public/flag.txt
	cp vmlinuz64 ../public
	cp initramfs.cpio.gz ../public
	cp run.sh ../public
	cp Dockerfile ../public

solve:
	cd ./solver && ./solve.sh localhost 1337

run:
	cd .. && ./run.sh

clean:
	rm -rf -- eraser
