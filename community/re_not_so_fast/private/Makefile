BUILD_IMG=re_not-so-fast-builder


all: clean build public

build:
	mkdir -p build_ctflearn build_ctfguide
	docker build -t $(BUILD_IMG) -f Dockerfile .

	docker run --rm -u $$(id -u):$$(id -g) -t -v $$PWD:/w -w /w/build_ctflearn $(BUILD_IMG) cmake -DCTF_PLATFORM=CTFLEARN ..
	docker run --rm -u $$(id -u):$$(id -g) -t -v $$PWD:/w -w /w/build_ctflearn $(BUILD_IMG) make -j4

	docker run --rm -u $$(id -u):$$(id -g) -t -v $$PWD:/w -w /w/build_ctfguide $(BUILD_IMG) cmake -DCTF_PLATFORM=CTFGUIDE ..
	docker run --rm -u $$(id -u):$$(id -g) -t -v $$PWD:/w -w /w/build_ctfguide $(BUILD_IMG) make -j4

	ls -lh build_ctfguide/src/not_so_fast build_ctflearn/src/not_so_fast

clean:
	rm -rf build_ctflearn build_ctfguide

public: build
	rm -rf -- ../public/*
	mkdir -p ../public/ctfguide ../public/ctflearn
	cp build_ctfguide/src/not_so_fast ../public/ctfguide
	cp build_ctflearn/src/not_so_fast ../public/ctflearn

	cd ../public/ctfguide && tar czf not_so_fast.tar.gz --remove-files -- *
	cd ../public/ctflearn && tar czf not_so_fast.tar.gz --remove-files -- *

solve:

	python solver/solve.py ./build_ctfguide/src/not_so_fast
	python solver/solve.py ./build_ctflearn/src/not_so_fast


.PHONY: build solve public 
