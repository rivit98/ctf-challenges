import sys

def xorr(input_file):
    content = open(input_file, "rb").read()
    xored = content[:256] + bytes([content[i] ^ 0x17 for i in range(256, len(content))])
    assert len(xored) == len(content)

    with open(input_file, "wb") as f:
        f.write(xored)


if __name__ == "__main__":
    xorr(sys.argv[1])
