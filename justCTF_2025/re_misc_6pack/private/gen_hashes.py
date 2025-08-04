from textwrap import wrap
from hashlib import sha256

def hash(text):
    return sha256(text.encode()).hexdigest()


def to_asm(hashed):
    return f"db {', '.join(f'0x{hashed[i:i+2]}' for i in range(0, len(hashed), 2))}"


def main(flag):
    flag_text = open(flag, "r").read().strip()
    assert len(flag_text) % 3 == 0

    chunks = wrap(flag_text[::-1], 3)
    print(chunks)
    hashed_chunks = [hash(chunk) for chunk in chunks]
    asm_chunks = [to_asm(hashed) for hashed in hashed_chunks]

    with open("stage3/hashed_data.asm", "w") as f:
        f.write(f'EXPECTED_HASHES:\n')
        f.write("\n".join(asm_chunks))
        f.write(f'\n\n')
        f.write(f"FLAG_LENGTH equ {len(flag_text)}\n")
        f.write(f"FLAG_CHUNKS equ {len(chunks)}\n")


if __name__ == "__main__":
    import sys
    main(sys.argv[1])
