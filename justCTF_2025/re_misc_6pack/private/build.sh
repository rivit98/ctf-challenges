#!/bin/bash

set -e

pushd stage1
go test -race . && go build -o ../6-pack -ldflags "-w -s" -gcflags "-l" -trimpath .
popd
python stripper.py ./6-pack

x86_64-w64-mingw32-gcc -Os -s -fno-ident -fdata-sections -ffreestanding -ffunction-sections -fno-unwind-tables -fno-asynchronous-unwind-tables stage2/stage2.c -o stage2.exe -Wl,--gc-sections  -Wl,--strip-all
x86_64-w64-mingw32-strip --strip-all stage2.exe 
upx ./stage2.exe

python gen_hashes.py ./flag.txt
pushd stage3
nasm -o ../sc.bin sc.asm
popd

# xor second part of sc
python xor_sc.py ./sc.bin

# encrypt sc using rc4 with key 31337
python enc_blob.py ./sc.bin ./sc.bin.encrypted 31337

# add shellcode (sc.asm) to section 
python add_section.py ./6-pack ./sc.bin.encrypted
