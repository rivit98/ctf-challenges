.PHONY: build public solve run clean

all: build public

build:
	docker build -t 6-pack-builder -f compile.Dockerfile .
	docker run -u $$(id -u):$$(id -g) --rm -it -v $$PWD:/w -w /w -e GOCACHE=/w/.cache 6-pack-builder ./build.sh

public:
	rm -rf ../public
	mkdir -p ../public
	cd ../public \
		&& ln -sf ../private/6-pack 6-pack \
		&& ln -sf ../private/Dockerfile Dockerfile \
		&& ln -sf ../private/dump.pcapng dump.pcapng

solve:
	./solver/solve.sh

clean:
	rm -rf -- 6-pack stage2.exe sc.bin sc.bin.encrypted .cache
