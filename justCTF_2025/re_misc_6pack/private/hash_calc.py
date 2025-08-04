import sys

def rol32(val, amt):
        return ( (val << amt) & 0xffffffff ) | ( ( val >> (32 - amt) ) & 0xffffffff )

def ror32(val, amt):
        return ( (val >> amt) & 0xffffffff ) | ( ( val << (32 - amt) ) & 0xffffffff )

def add32(val, amt):
        return (val + amt) & 0xffffffff

def hash_export(name):
    result = 0
    index = 0
    while(index < len(name)):
        result  = add32(ror32(result, 13), ord(name[index]) & 0xff)
        index += 1
    return result

def main():
    print(hex(hash_export(sys.argv[1])))

if __name__ == '__main__':
	main()