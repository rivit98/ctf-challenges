from pathlib import Path
import sys
from textwrap import wrap


def main(flag_file, out_dir):
    flag = flag_file.read_text().strip()
    
    chunk_size = 4
    for i, chunk in enumerate(wrap(flag, chunk_size)):
        print(chunk)
        chunk_file = out_dir / f'flag{i:02d}'
        chunk_file.write_text(chunk)


if __name__ == "__main__":
    
    main(Path(sys.argv[1]), Path(sys.argv[2]))
