all: clean build public

build:
	mkdir -p build

	cp store.vault ./build/store.vault.ctflearn
	cp store.vault ./build/store.vault.ctfguide

	python ./solver/nvault.py patch ./build/store.vault.ctflearn Player $(shell cat flag_ctflearn.txt)
	python ./solver/nvault.py patch ./build/store.vault.ctfguide Player $(shell cat flag_ctfguide.txt)

clean:
	rm -rf build_ctflearn build_ctfguide

public: build
	rm -rf -- ../public/*
	mkdir -p ../public/ctfguide/addons/amxmodx/data/vault
	mkdir -p ../public/ctfguide/addons/amxmodx/plugins
	cp secret_store.amxx ../public/ctfguide/addons/amxmodx/plugins
	cp -r ../public/ctfguide ../public/ctflearn

	cp ./build/store.vault.ctfguide ../public/ctfguide/addons/amxmodx/data/vault/store.vault
	cp ./build/store.vault.ctflearn ../public/ctflearn/addons/amxmodx/data/vault/store.vault

	cd ../public/ctfguide && tar czf old_times.tar.gz --remove-files -- *
	cd ../public/ctflearn && tar czf old_times.tar.gz --remove-files -- *

solve:

	python ./solver/nvault.py read ./build/store.vault.ctflearn
	python ./solver/nvault.py read ./build/store.vault.ctfguide


.PHONY: build solve public 
