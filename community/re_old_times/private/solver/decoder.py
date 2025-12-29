from z3 import *
from textwrap import wrap
from itertools import cycle
import sys


def stage1(input, nick):
    dexored = list(input)

    for i in range(0, len(dexored), 2):
        if i + 1 >= len(dexored):
            break

        dexored[i], dexored[i + 1] = dexored[i + 1], dexored[i]


    dexored = [a ^ b for a, b in zip(dexored, cycle(map(ord, nick)))]
    password = ''.join(map(chr, dexored))
    return password


def stage2(nick, encoded):
    const = 11
    out = []
    output_ints = list(map(lambda v: int(v, 16), wrap(encoded, 2)))
    xs = BitVecs(' '.join([f'x{i}' for i in range(len(output_ints))]), 32)
    s = Solver()
    for i in range(len(output_ints)):
        s.add(xs[i] <= 0xFF, xs[i] >= 0x0)
        s.add(
                (
                    ((xs[i] & 0xF) ^ const) << 4 | (LShR((xs[i] & 0xF0), 4) ^ (~(const) & 0xF))
                ) 
                == output_ints[i]
            )

    while True:
        if s.check() == sat:
            recovered = [s.model()[v].as_long() for v in xs]
            out.append(stage1(recovered, nick))
            s.add(Or([s.model()[v].as_long() != v for v in xs]))
        else:
            break

    return out


def decode(nick, passwd_encoded):
    return stage2(nick, passwd_encoded)[0]


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("python decode.py passwd_hash nick")
        exit(1)

    dec = decode(sys.argv[2], sys.argv[1])
    print(dec)
