import resource, sys
from binascii import unhexlify
resource.setrlimit(resource.RLIMIT_STACK, (2**29, -1))
sys.setrecursionlimit(10**6)
sys.set_int_max_str_digits(10**6)

expected_num = int.from_bytes(open("./flag.txt", "rb").read())

def f(x):
    if x == 0:
        return 2
    
    if x <= 1:
        return 1
    
    return g(x-1) + 73 * x ** 5 + 8 * x ** 3 + x - 4

def g(x):
    if x <= 1:
        return 1
    return f(x-1) + 3 * f(x-2) - 5 * f(x-3) + 3 * x ** 4


cache_f = {}
cache_g = {}

def ff_runner(x):
    for i in range(-10, x):
        cache_f[i] = ff(i)
        cache_g[i] = gg(i)

    return ff(x)


def ff(x):
    global cache_f, cache_g

    if x == 0:
        return 2

    if x <= 1:
        return 1

    return cache_g[x-1] + 73 * x ** 5 + 8 * x ** 3 + x - 4


def gg(x):
    global cache_f, cache_g

    if x <= 1:
        return 1

    return cache_f[x-1] + 3 * cache_f[x-2] - 5 * cache_f[x-3] + 3 * x ** 4


if __name__ == "__main__":
    a = int(sys.argv[1])
    mod = 12871709638832864416674237492708808074465131233250468097567609804146306910998417223517320307084142930385333755674444057095681119233485961920941215894136808839080569675919567597231
    correction = 805129649450289111374098215345043938348341847793365469885914570440914675704049341968773123354333661444680237475120349087680072042981825910641377252873686258216120616639500404381

    if a > 100:
        a = ff_runner(a) % mod + correction
        try:
            b = f(a) % mod + correction

            assert a == b
        except Exception as e:
            print(e)
            pass
    else:
        a = ff_runner(a)
        try:
            b = f(a)

            assert a == b
        except Exception as e:
            print(e)
            pass

    print(a)
    print(unhexlify(hex(a)[2:]).decode())