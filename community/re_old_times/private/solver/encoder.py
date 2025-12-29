from itertools import cycle
import sys

from decoder import decode

def encode(nick, passwd):
    return ''.join(map(lambda v: f'%02x' % v, stage3(stage1(passwd, nick))))


def stage1(passwd, nick):
    # return list(map(ord, passwd))
    xored = [a ^ b for a, b in zip(map(ord, passwd), cycle(map(ord, nick)))]
    for i in range(0, len(passwd), 2):
        if i + 1 >= len(passwd):
            break

        xored[i], xored[i + 1] = xored[i + 1], xored[i]

    return xored

def bit_not(n, numbits=8):
    return (1 << numbits) - 1 - n

def stage3(input):
    const = 11

    for i, c in enumerate(input):
        a = ((c & 0xF) ^ const) << 4 
        b = (((c & 0xF0) >> 4) ^ (bit_not(const) & 0xF))
        input[i] = a |  b

    return input


if __name__ == '__main__':
    if len(sys.argv) == 3:
        print(encode(sys.argv[2], sys.argv[1]))
        exit(1)

    users = [
        ("Rivit", "admin1337"),
        ('Pwner', 'this is not a pwn category'),
        ('Smurf', 'noobs'),
        ("Player", "CTFlearn{g00d_0ld_c0un73r_57r1k3}"),
        ('Defuser', 'useless feature'),
        ('Samurai', 'what is it'),
        ('Sniper', 'asdfasdfasdf'),
        ('Deadeye', 'what am I supposed to store here?'),
    ]

    for u, p in users:
        enc = encode(u, p)
        print(f'{{"{u}", "{enc}"}},')
        print(decode(u, enc) == p)
