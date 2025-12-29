from pwn import *

elf = context.binary = ELF('./task')

if args.GDB:
	p = gdb.debug(elf.path, '\n'.join([
		"b *main+182",
		"c"
	]))
elif args.REMOTE:
	host, port = args.get("HOST", "localhost"), args.get("PORT", 5000)
	p = remote(host, port)
else:
	p = process(elf.path)

# https://www.wolframalpha.com/input?i=mod%28212103456793011*+x%2C+2%5E64%29+%3D+183057226632645
p.sendline(b'9585860797856392871')

print(p.clean(1.0))

