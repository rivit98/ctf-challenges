
from pathlib import Path
import sys

def main(binary):
    data = Path(binary).read_bytes()

    token = b'main.'
    data = data.replace(token, b'\x00'*len(token))
    Path(binary).write_bytes(data)


if __name__ == "__main__":
    main(sys.argv[1])